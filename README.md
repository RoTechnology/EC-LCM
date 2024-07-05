# EC-LCM
ECTAKS implementation in C

## Overview
The EC-LCM (Elliptic Curve - Lightweight Cryptography Module) is a software component proposed to secure communications for resource-constrained devices through the implementation of a cryptographic scheme with the Elliptic Curve approach.

The EC-LCM is built for a specific [Energy ECS](https://energyecs.eu) Cyber Security Issues case study.

## How it works
The  component offers security features for communications between different entities by encrypting and decrypting the data that is exchanged between them.
Moreover, the component verifies the authenticity of the message through a digital signature.

### How to use
To correctly use the library follow these steps:
1. Include the .h files in [EC-LCM/src/windows](https://github.com/RoTechnology/EC-LCM/tree/main/src/windows) into the project folder
2. Include the linked library in [EC-LCM/lib](https://github.com/RoTechnology/EC-LCM/tree/main/lib) folder into the lib folder
3. Compile main.c in test folder and run your code
