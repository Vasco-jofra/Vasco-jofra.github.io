---
title: "(full) Escaping well-configured VSCode extensions for profit (part 2)"
tags: ["VSCode", "path_traversal", "CVE"]
published: false
---

In part one of this two-part series, we escaped Webviews in real-world misconfigured VSCode extensions. But can we still escape extensions if they are well-configured?

In this post, we’ll demonstrate how I bypassed a Webview’s `localResourceRoots` by exploiting small URL parsing differences between the browser---i.e., the [Electron](https://www.electronjs.org/)-created Chromium instance where VSCode and its Webviews run---and other VSCode logic and an over-reliance on the browser to do path normalization. This bypass allows an attacker with JavaScript execution inside a Webview to read files anywhere in the system, including those outside the `localResourceRoots`. Microsoft assigned this bug [CVE-2022-41042](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2022-41042) and awarded us a bounty of $7,500 (about $2,500 per minute of bug finding).

## Finding the issue
While exploiting the vulnerabilities detailed in the last post, I wondered if there could be bugs in VSCode itself that would allow us to bypass any security feature that limits what a Webview can do. In particular, I was curious if we could still exploit the bug we found in the SARIF Viewer extension (vulnerability 1 in the last post) if there were stricter rules in the Webview’s `localResourceRoots` option. 

From last post’s SARIF viewer exploit, we learned that you can always exfiltrate files using DNS prefetches if you have the following preconditions:
 - You can execute JavaScript in a Webview. This enables you to add `<link>` tags to the DOM.
 - The CSP’s `connect-src` directive has the `.vscode-resource.vscode-cdn.net` source. This enables you to `fetch` local files.

**…Files within the `localResourceRoots` folders, that is**! This option limits the folders from which a Webview can read files, and, in the SARIF viewer, it was configured to limit, well… nothing. But such a permissive `localResourceRoots` is rare. Most extensions only allow access to files in the current workspace and in the extensions folder (the default values for the `localResourceRoots` option).

Recall that Webviews read files by fetching the `https://file+.vscode-resource.vscode-cdn.net` "fake" domain, as shown in the example below.

```javascript
fetch("https://file+.vscode-resource.vscode-cdn.net/<file_path>")
    .then(res => res.text())
    .then(text => console.log(text))
```
<p class="figure-caption">Example of how to fetch a file from a VSCode extension Webview</p>

Without even looking at how the code enforced the `localResourceRoots` option, I started playing around with different path traversal payloads with the goal of escaping from the root directories where we are imprisoned. I tried a few payloads, such as:
 - `/etc/passwd`
 - `/../../../../../etc/passwd`
 - `/<valid_root>/../../../../../etc/passwd`

As I expected, this didn't work. The browser normalized the request’s path even before it reached VSCode, as shown in the image below.

![](/assets/img/2023-02-23-escaping-well-configured-VSCode-extensions/image2.png)
<p class="figure-caption">Unsuccessful fetches of the /etc/passwd file</p>

I started trying different variants that the browser would not normalize, but that some VSCode logic might consider a valid path. In about three minutes, to my surprise, I found out that using `%2f..` instead of `/..`  allowed us to escape the root folder(!!!).

![](/assets/img/2023-02-23-escaping-well-configured-VSCode-extensions/image1.png)
<p class="figure-caption">Successful fetch of the /etc/passwd file when using the / character URL encoded as %2f</p>

We’ve escaped! We can now fetch files from anywhere in the filesystem. But why did this work? VSCode seems to decode the `%2f`, but I couldn't really understand what was happening under the hood. My initial assumption was that the function that reads the file (e.g., the `fs.readFile` function) was decoding the `%2f`, while the path normalization function did not. As we’ll see, this was not a bad guess, but not quite the real cause.

## Root cause analysis
Let's start from the beginning and see how VSCode handles `vscode-resource.vscode-cdn.net` requests---remember, this is not a real domain.

It all starts in the [service worker](https://github.com/microsoft/vscode/blob/d00804ec9b15b4a8ee064f601de1aa4a31510e55/src/vs/workbench/contrib/webview/browser/pre/service-worker.js#L170-L324) running on the Webview. This service worker intercepts every Webview’s request to the `vscode-resource.vscode-cdn.net` domain and transforms it into a `postMessage('load-resource')` to the main VSCode thread.

```javascript
sw.addEventListener('fetch', (event) => {
	const requestUrl = new URL(event.request.url);
	if (requestUrl.protocol === 'https:' && requestUrl.hostname.endsWith('.' + resourceBaseAuthority)) { // resourceBaseAuthority = `vscode-resource.vscode-cdn.net`
		switch (event.request.method) {
			case 'GET':
			case 'HEAD': {
				// <REDACTED>
				return event.respondWith(processResourceRequest(event, {
					scheme,
					authority,
					path: requestUrl.pathname,
					query: requestUrl.search.replace(/^\?/, ''),
				}));
			}

// <REDACTED
async function processResourceRequest(event, requestUrlComponents) {
		// <REDACTED
		parentClient.postMessage({
			channel: 'load-resource',
			id: requestId,
			scheme: requestUrlComponents.scheme,
			authority: requestUrlComponents.authority,
			path: requestUrlComponents.path,
			query: requestUrlComponents.query,
			ifNoneMatch: cached?.headers.get('ETag'),
		});
		// <REDACTED
}
```
<p class="figure-caption">Code from the Webview’s service worker that intercepts fetch requests that start with vscode-resource.vscode-cdn.net and transforms them in a postMessage to the main VSCode thread (<a href="https://github.com/microsoft/vscode/blob/7666d7acd4cb7382c6e4749166f713d1226ccd99/src/vs/workbench/contrib/webview/browser/pre/service-worker.js#L170-L373">source</a>)</p>

VSCode will handle the `postMessage('load-resource')` call by building a `URL` object and calling `loadResource`, as shown below.
```javascript
this._register(this.on(WebviewMessageChannels.loadResource, async (entry: { id: number; path: string; query: string; scheme: string; authority: string; ifNoneMatch?: string }) => {
	try {
		// Restore the authority we previously encoded
		const authority = decodeAuthority(entry.authority);
		const uri = URI.from({
			scheme: entry.scheme,
			authority: authority,
			path: decodeURIComponent(entry.path), // This gets re-encoded
			query: entry.query ? decodeURIComponent(entry.query) : entry.query,
		});
		this.loadResource(entry.id, uri, entry.ifNoneMatch);
	} catch (e) {
		// <REDACTED>
	}
}));
```
<p class="figure-caption">VSCode code that handles a load-resource postMessage. Highlighted in red is the code that decodes the fetched path---the first reason why our exploit works (<a href="https://github.com/microsoft/vscode/blob/7666d7acd4cb7382c6e4749166f713d1226ccd99/src/vs/workbench/contrib/webview/browser/webviewElement.ts#L357-L375">source</a>)</p>

Notice that the URL path is decoded with `decodeURIComponent`. This is why our `%2f` is decoded! But this alone still doesn’t explain why the path traversal works. Normalizing the path before checking if the path belongs to one of the roots would prevent our exploit. Let’s keep going.

The `loadResource` function simply calls `loadLocalResource` with `roots: localResourceRoots`.

```javascript
private async loadResource(id: number, uri: URI, ifNoneMatch: string | undefined) {
	try {
		const result = await loadLocalResource(uri, {
			ifNoneMatch,
			roots: this.content.options.localResourceRoots || [],
		}, this._fileService, this._logService, this._resourceLoadingCts.token);
```
<p class="figure-caption">The loadResource function calling loadLocalResource with the localResourceRoots option (<a href="https://github.com/microsoft/vscode/blob/7666d7acd4cb7382c6e4749166f713d1226ccd99/src/vs/workbench/contrib/webview/browser/webviewElement.ts#L811-L816">source</a>)</p>

Then, the `loadLocalResource` function calls `getResourceToLoad`, which will iterate over each root in `localResourceRoots` and check if the requested path is in one of these roots. If all checks pass, `loadLocalResource` reads and returns the file contents, as shown below.

```javascript
export async function loadLocalResource(/*<REDACTED>*/) {
	const resourceToLoad = getResourceToLoad(requestUri, options.roots);
	if (!resourceToLoad) {
		return WebviewResourceResponse.AccessDenied;
	}

	// <REDACTED>

	try {
		const result = await fileService.readFileStream(resourceToLoad, { etag: options.ifNoneMatch }, token);
		return new WebviewResourceResponse.StreamSuccess(result.value, result.etag, result.mtime, mime);
	} catch (err) {
		// <REDACTED>
       }

function getResourceToLoad(requestUri: URI, roots: ReadonlyArray<URI>) {
	for (const root of roots) {
		if (containsResource(root, requestUri)) {
			return normalizeResourcePath(requestUri);
		}
	}

	return undefined;
}

function containsResource(root: URI, resource: URI): boolean {
	if (root.scheme !== resource.scheme) {
		return false;
	}

	let rootPath = root.fsPath + (root.fsPath.endsWith(sep) ? '' : sep);
	let resourceFsPath = resource.fsPath;

	if (isUNC(root.fsPath) && isUNC(resource.fsPath)) {
		rootPath = rootPath.toLowerCase();
		resourceFsPath = resourceFsPath.toLowerCase();
	}

	return resourceFsPath.startsWith(rootPath);
}
```
<p class="figure-caption">Code that checks if a path is within the expected root folders and returns the file contents on success. Notice the .startsWith check without any prior normalization---the second reason our exploit works.(<a href="https://github.com/microsoft/vscode/blob/7666d7acd4cb7382c6e4749166f713d1226ccd99/src/vs/workbench/contrib/webview/browser/resourceLoading.ts#L45-L130">source</a>)</p>

There is no path normalization, and the root check is done with `resourceFsPath.startsWith(rootPath)`. This is why our path traversal works! If our path is `<valid-root-path>/../../../../../etc/issue`, we'll pass the `.startsWith` check even though our path points to somewhere outside of the root.

In summary, two mistakes allow our exploit:
 - The VSCode extension calls `decodeURIComponent(path)` on the path, decoding `%2f` to `/`. This allows us to bypass the browser's normalization and introduce `../` sequences in the path.
 - The `containsResource` function checks that the requested file is within the expected `localResourceRoots` folder with the `startsWith` function without first normalizing the path (i.e., removing the `../` sequences). This allows us to traverse outside the root with a payload such as `<valid-root-path>/../../../<wanted-path>`.

This bug is hard to spot by just manually auditing the code. The layers of abstraction and all the message passing mask where our data flows through, as well as some of the critical details that make the exploit work. This is why evaluating and testing software by executing the code and observing its behavior at runtime---dynamic analysis---is such an important part of auditing complex systems. Finding this bug through static analysis would require defining sources, sinks, sanitizers, and an interprocedural engine capable of understanding data that is passed in `postMessage` calls. After all that work, you may still end up with a lot of false positives and false negatives; we use static analysis tools extensively at Trail of Bits, but they’re not the right tool for this job.

## Recommendations for preventing path traversals
In the last blog’s third vulnerability, we examined a path traversal vulnerability caused by parsing a URL’s query string with flawed hand-coded logic that allowed us to circumvent the path normalization done by the browser. These bugs are very similar; in both cases, URL parsing differences and the reliance on the browser to do path normalization resulted in path traversal vulnerabilities with critical consequences.

So, when handling URLs, we recommend following these principles:
 - **Parse the URL from the path with an appropriate object** (e.g., JavaScript’s URL class) instead of hand-coded logic.
 - **Do not transform any URL components after normalization** unless there is a very good reason to do so. As we've seen, even decoding the path with a call to `decodeURIComponent(path)` was enough to fully bypass the `localResourceRoots` feature since other parts of the code had assumptions that the browser would have normalized the path. If you want to read more about URL parsing discrepancies and how they can lead to critical bugs, I recommend reading [A New Era of SSRF](https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf) by Orange Tsai and [Exploiting URL Parsing Confusion](https://claroty.com/team82/research/exploiting-url-parsing-confusion). 
 - **Always normalize the file path before checking if the file is within the expected root**. Doing both operations together, ideally in the same encapsulated function, ensures that no future or existing code will transform the path in any way that invalidates the normalization operation.

## Timeline
 - September 7, 2022: Reported the bug to Microsoft
 - September 16, 2022: Microsoft confirmed the behavior of the report and mentioned that the case is being reviewed for a possible bounty award
 - September 20, 2022: Microsoft marks the report as out-of-scope for a bounty because “VS code extensions are not eligible for bounty award”
 - September 21, 2022: I reply mentioning that the bug is in the way VSCode interacts with extensions, but not in a VSCode extension
 - September 24, 2022: Microsoft acknowledges their mistake and awards the bug a $7,500 bounty.
 - October 11, 2022: Microsoft fixes the bug in [PR #163327](https://github.com/microsoft/vscode/pull/163327) and assigns it [CVE-2022-41042](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2022-41042)