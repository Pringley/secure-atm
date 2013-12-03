# Secure ATM protocol

## Usage

Install libraries on 64-bit Ubuntu using:

    sudo apt-get install g++ g++-multilib libcrypto++-dev:i386

On 32-bit Ubuntu, one can simply run:

    sudo apt-get install g++ libcrypto++-dev

Compile using:

    make

This will generate three executables: `atm`, `proxy`, and `bank`.

## Authors

Written by:

-   Drew McGowen
-   Ben Pringle
-   Adil Soubki

With boilerplate code from:

-   Andrew Zonenberg

This is a project for CSCI-4971 at Rensselaer Polytechnic Institute, a class
instructed by Bülent Yener.
