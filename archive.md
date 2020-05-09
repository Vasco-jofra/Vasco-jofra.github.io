---
layout: page
title: Archive
---

<section>
  {% if site.posts[0] %}

    <h4>{{ site.posts[0].date | date: '%Y' }}</h4>

    {%for post in site.posts %}
      {% unless post.next %}
        <ul>
      {% else %}
        {% capture year %}{{ post.date | date: '%Y' }}{% endcapture %}
        {% capture nyear %}{{ post.next.date | date: '%Y' }}{% endcapture %}
        {% if year != nyear %}
          </ul>
          <h4>{{ year }}</h4>
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