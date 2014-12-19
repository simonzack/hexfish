# HexFish

HexFish is a FiSH/MirCryption-compatible python 3 encryption plugin for xchat/hexchat written in 100% pure python.

## Usage
Type `/fish -h` in any irc window.

## Features

- Cipher-block chaining (CBC) key exchange setting & encryption.
- `/me` `/msg` `/notice` encryption & decryption.
- Key exchange protection.
- Stealth mode (don't reply to key exchanges).
- Nick aliases for nick changes.

## Configuration
The config file, `fish.json` is located in the hexchat configuration directory. See `config.py` for the default settings.

## Dependencies
PyCrypto, tabulate

## Authors
Written by simonzack, originally inspired by py-fishcrypt.
