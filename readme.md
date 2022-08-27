# HexFish
*HexFish* is a *FiSH*/*MirCryption*-compatible *Python* encryption plugin, for *XChat*/*HexChat*. Written in 100% pure *Python*.

## Development Setup
To setup the project for development, run:

    $ cd hexfish/
    $ pdm install

## Usage
Type `/fish -h` in any *IRC* window.

## Features
- Cipher-Block Chaining (CBC) key exchange setting & encryption.
- `/me` `/msg` `/notice` encryption & decryption.
- Key exchange protection.
- Stealth mode: Don't reply to key exchanges.
- Nick aliases for nick changes.

## Configuration
The config file `fish.json` is located in the *HexChat* configuration directory. See `config.py` for default settings.

## Authors
Written by simonzack. Originally inspired by `py-fishcrypt`.
