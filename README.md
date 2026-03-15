# KeyAuth Example ( PROTECTED ) 

This project is a basic example of how I structure authentication and protection in a C++ application using the KeyAuth API.

I’m sharing it because a lot of people overcomplicate app security. In reality, layering a few simple checks can already prevent common issues like basic patching, license swapping, and repeated login attempts.

This won’t stop experienced attackers, but it helps against common automated tools and simple tampering.

## How It Helps Protect the Application

This setup adds multiple small security layers instead of relying on just one check. Together, they help:

- Prevent unauthorized access without a valid license
- Stop basic DLL patchers that modify authentication responses
- Detect simple configuration tampering
- Limit brute-force login attempts with a lockout system
- Verify that the user’s subscription is valid
- Monitor the session to ensure it stays authenticated
- Securely terminate the program if something fails

Each layer alone is simple — but combined, they make casual tampering much harder.

## What This Includes

- License-based authentication (KeyAuth)
- Subscription validation
- Basic integrity checks for core configuration values
- Simple login lockout system
- Session validation thread
- Memory cleanup for sensitive strings
- Secure termination using `__fastfail`

## How It Works (Simple Overview)

1. The program initializes the authentication system.
2. It checks that core configuration values haven’t been modified.
3. The user is prompted to enter a license key.
4. The key is verified with the server.
5. The user’s subscription is checked.
6. Background threads monitor the session status.
7. Failed login attempts trigger a temporary lockout.
8. If anything fails, the program exits securely.

## Requirements

- Windows
- C++17 or newer
- KeyAuth C++ library (v1.3)
- Dependencies included in the project

KeyAuth Library:  
https://github.com/KeyAuth/keyauth-cpp-library-1.3API

## Notes

This is meant to demonstrate a simple protection structure.

Real security should always rely heavily on server-side validation. Client-side checks can help, but they should not be the only layer of protection.

## Purpose

This project is mainly for learning and demonstration.  
Feel free to modify and improve it for your own use.
