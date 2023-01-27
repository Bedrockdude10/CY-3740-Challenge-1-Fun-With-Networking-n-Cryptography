This repo demonstrates my programming in C, as well as network programming and cryptography.

This is my code for Challenge 1 in my CY 3740: Systems Security class at Northeastern University.
For this project, we had to use the C socket library to open a TCP connection to a server, encrypt a message using the
Sodium Cyrptography Library, receive the message back, and decrypt the message's payload to verify the integrity of the 
message. The scenario for the challenge is that someone has infiltrated the network, and is somehow modifying the 
messages being sent between the client and server. As such, the first few hundred messages received by the client from 
the server fail the integrity check - this is why I send & receive the message 1000 times. After receiving an
uncorrupted message from the server, I hash and base64 encode the message using functions from the Sodium library to
get a printable string.