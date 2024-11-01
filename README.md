![build status](https://github.com/buckfullingham/cc.fyi.zip.cracker/actions/workflows/build.yml/badge.svg)

# Build Your Own Zip File Cracker

This is a solution to the problem posed at https://codingchallenges.fyi/challenges/challenge-zip-cracker

## Features

This cracker will find the first password that decrypts an entry within a given zip file.  The passwords can either be
provided by text file (separated by single newline character), or can be brute-forced using a user-supplied alphabet.
Brute-forcing will utilise multiple threads.

### Operation
#### Options
1. -z zip_file
2. -d dict_file; or
3. -b max_len:regex

#### Examples
```
zip-cracker -z test.zip -d crackstation-human-only.txt
zip-cracker -z test.zip -b 8:[a-z]
zip-cracker -z test.zip -b 8:[[:alnum:]]
```
