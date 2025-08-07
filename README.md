# BACman 🕵️‍♂️ - A Burp Extension for BAC Testing

BACman is a simple Burp Suite extension designed to make your life easier.

It helps you organize your testing workflow and quickly check endpoints for BAC issues by simplifying the process of replaying requests with different user contexts.

## Why Use It?

-   **Stop the Juggle:** No more manually copying and pasting cookies or tokens between different tools.
-   **Clear Workflow:** Keep your BAC testing organized in a single tab.
-   **Find Bugs Faster:** A simpler process means more time for analysis and finding critical vulnerabilities.

## Features

-   **Seamless Burp Integration:** Fits right into your existing workflow.
-   **Send to BACman:** Easily send any request from Burp's tools (Proxy, Repeater, etc.) to the BACman tab.
-   **Easy Session Swapping:** Quickly modify headers and replay requests to test for authorization flaws.

## Installation

This extension is a Python script, so you'll need Jython to run it.

1.  **Get Jython:**
    -   Download the standalone Jython JAR from the [official website](https://www.jython.org/download).

2.  **Configure Burp:**
    -   Go to the `Extender` -> `Options` tab.
    -   In the "Python Environment" section, click "Select file" and point it to the `jython-standalone-xxx.jar` file you downloaded.

3.  **Add the Extension:**
    -   Go to the `Extender` -> `Extensions` tab.
    -   Click `Add`.
    -   Set the "Extension type" to `Python`.
    -   Select the `BACman.py` file.
    -   The extension should now be loaded and you'll see a new "BACman" tab.

## How to Use

1.  **Browse the Target App:** Use your browser to navigate the web application. Log in with different user roles (e.g., an admin and a regular user) to capture their session cookies/tokens.

2.  **Send to BACman:** Find a request you want to test (e.g., a request to an admin-only page). Right-click it and choose `Send to BACman`.

3.  **Test for BAC:**
    -   Go to the "BACman" tab.
    -   Take the request you just sent.
    -   Replace the session cookie or `Authorization` header with the one from a lower-privileged user.
    -   Hit the "Send" button.

4.  **Analyze the Result:** Did you get a `200 OK` instead of a `403 Forbidden`? You've likely found a Broken Access Control vulnerability. The response will be shown for you to analyze.

## Contributing

Found a bug or have an idea for a new feature? Feel free to open an issue or submit a pull request.

## Disclaimer

This tool is intended for legitimate security testing and educational purposes only. You are responsible for your own actions. Do not use this tool on any system you do not have permission to test.

## License

This project is licensed under the MIT License.
