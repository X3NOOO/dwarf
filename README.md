# dwarf

```txt
     __                ___
 ___/ /    _____ _____/ _/
/ _  / |/|/ / _ `/ __/ _/
\_,_/|__,__/\_,_/_/ /_/
```

A simple link shortener.

![screenshot](https://raw.githubusercontent.com/X3NOOO/dwarf/master/dwarf.png)

## Features

- Both auto-generated and custom shortlink.
- Limit the number of visits for your shortlink.
- Ability to set an expiration date.
- Password protection of your shortlink.

## Installation

1. Copy `index.php` and `style.css` into your html directory.
2. Setup rewrites for your web server (nginx example below).

```nginx
location / {
    try_files $uri $uri/ /?$args;
}
```

## Donation

- XMR: `8BrqGJBJ9cAKWLhaZws37AbCZtKVg2cfq8JpNr6GmeuZYZUUHLgn2L4PLxg1eZHvzMLNncyYpduVWHb8X49qx8vmAL5oanL`
