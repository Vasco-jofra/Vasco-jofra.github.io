---
layout: page
title: Archive
---

<section>
  {% if site.posts[0] %}

    <h2>{{ site.posts[0].date | date: '%Y' }}</h2>

    {%for post in site.posts %}
      {% unless post.next %}
        <ul>
      {% else %}
        {% capture year %}{{ post.date | date: '%Y' }}{% endcapture %}
        {% capture nyear %}{{ post.next.date | date: '%Y' }}{% endcapture %}
        {% if year != nyear %}
          </ul>
          <h2>{{ year }}</h2>
          <ul>
        {% endif %}
      {% endunless %}

      <li>
        <time> {{ post.date | date:"%d %b" }} | </time>
        <a href="{{ post.url }}"> {{ post.title }} </a>
      </li>
    {% endfor %}
    </ul>

  {% endif %}
</section>