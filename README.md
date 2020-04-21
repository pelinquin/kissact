# KISSACT - Keep It Stupid Simple Automatic Contact Tracing

## Introduction

KISSACT is a contribution to the projects of apps for smartphones (+connected objects) and server (HTTP) of health authorities to allow an automatic and **individualized** processing of preventive measures against a pandemic, like the one of Covid-19.

The global economic cost of undifferentiated containment measures is gigantic: tens of thousands of billions of dollars. Moreover, undifferentiated deconfinement, which could allow the pandemic to restart, leads to equally high costs in the long run. In the end, the prosperity of entire countries, the freedom of peoples and human health are threatened. For the public authorities, the investment in the development of a **contact tracing** system is ridiculously low given the economic stakes. However, my contribution is voluntary.

In this context, even without previous experience, the use of a digital tool is necessary to automate and improve the relevance of classic and manual 'contact tracing' operations conducted by epidemiologists via interviews.

KISSACT is to date (April 21, 2020) a simple 100-line Python program.
It is the reference for implementations for:
- an **app** for smartphone (iOs and Android) with BLE contacts,
- a web **server**  (backend under the responsibility of epidemiologists).

Note that the app can work on the move without a SIM card. You need a wired or Wifi connection to synchronize with the server in the evening, for example.

The KISSACT app incorporates a contagion model as a result of past contacts of equipped persons. Epidemiologists are responsible for the daily parameterization of this model, which may differ from region to region. 
The app provides a list of individualized, daily instructions to be observed by the smartphone owner via the relay of the server, without revealing the identity of the persons. 

Knowing that the efficiency of a contact tracing app is a quadratic function of its usage rate, the wearing of the app in times of pandemic should not be left to the choice of citizens. The situation is analogous to a vaccination. Refusal to be vaccinated, as well as the refusal to activate this device when travelling, poses a collective danger to public health.

On the other hand, there may be competition between projects for the development of digital contact tracing solutions, but when it comes to actual implementation, it will be essential that all choose the same system, with at least apps that are compatible with each other.

Today (April 21, 2020), the DP-3T project is the most advanced and the most widespread. The ROBERT project presents only protocol documentation and suffers from a more centralized approach.
Our objective with KISSACT is not to replace these projects financed and supported by public authorities, but to force to take into account some citizen or scientific requirements that might have been forgotten.

KISSACT would simply like to improve the transparency and understanding of Contact Tracing protocols. 
I invite all curious people, even young people, to dive into the 100-line Python code and run the example provided with the four virtual users: Alice, Bob, Carol and David.

## Stroll through the code ## 

This code simulates everything: the users, the epidemiological models, the server, the time. Like any model, it is incomplete, reductive, but useful to program an app and a server respecting the principles of optimality engineering.

A user is created by a *ctApp* object with a nickname and the age of its owner. 
This data, as well as the geographical positions of the movements remain in the memory of the phone and are never transmitted outside, neither to the server, nor to the manufacturers of smartphones, nor to the governments.

A *serverCT* server object is created, under the responsibility of the health authorities. This server, which can be described as public, does not contain anything secret about people or the operation of the apps. It is simply protected from any malicious person who would want to modify or delete this data shared between all. 

There are no time constants in the KISSACT code. The 'next' method, which simulates the environment, changes the BLE ID for all users. Real apps only change their Id as a function of time.

The 'contact' function simulates a contact between two people by specifying the duration of this contact, the proximity (inverse of the distance) of this contact. The contacts are recorded symmetrically as in real life.

A malicious person can spy on messages sent from a large distance using a directional antenna, without sending a message.
They can also send a large number of messages (DOS attack) to saturate nearby smartphones.
The common Apple-Google API should make it easier to protect against these attacks.

In the beginning, the four people stay separated.
Then Alice meets Bob, then Bob has lunch with Carol.
Some time later he walks with her in the park.
Finally David visits Alice.

Suppose Carol develops symptoms at Covid-19. Her doctor gives her a right to be tested and it turns out she is positive. Her doctor asks the server to generate a disposable code, which will be used by Carol to declare that she is contagious. This code prevents anyone, including the robot, from declaring herself contagious.

Carole is free to inform the server of past contacts. Depending on the place or the period, she may decide to hide some contacts to transmit.
In our example, David is also sick and decides that instead of providing a list, he prefers to give his root key, which will allow the server to reconstruct his entire contact history.
The server will publicly share the contact history of infected people, without any geolocation data, without knowing the identity or even the number of infected people.

After updating the new server data, the app is able to propose a set of individual measures to be taken. However, there is no mechanism to verify the effective application of the recommended measures.
If with this and other tools, Rt durably drops below 1 or if a vaccine is found, then there will be fewer and fewer Convid-plus declarations on the server. The risk for everyone will tend towards zero. The app will no longer be useful.

On the app interface, I recommend to display a "bubble" indicator (see https://adox.io/bulle.pdf) that tells the bearer if he respects the distancing rules or not.


## Extensions

Why does the *ctApp* object have a *balance* attribute?
It will eventually be possible, with a small cryptographic layer and during a BLE contact, to make an instantaneous digital (micro)payment, within the framework of a mutual credit system. Unlike a currency, this system allows you to have an account with a negative balance, up to a certain limit.

Payment is not possible in the 'red' zone, or if there are more than two people in the vicinity.
The destination of the payment is thus identified and the transaction validated by the contact. The keys are exchanged and one byte of the identifier is used to fill in the price (maximum 256 units). 
The app displays the user's current balance.

This extension requires a declaration to a civil registry office in order to be able to discriminate between humans and authorise only one account per person, like the French LivretA. Such an interest-free, lifetime credit line advance is not possible for legal entities, robots or AI.

The monetary unit is universal. It is initialized with an approximate energy value of 1kW, or about 10 euro cents. The price of each product exchangeable through this accounting system is free and maximum of about 25€.

Payment can also be made through the use of a shared object such as a distributor, a counter or a resource carrier. For this reason it must be possible to implement the KISSACT protocol on a BLE device other than a smartphone. Several projects are under study, based on ESP32, nRF52 or with a RaspberryPi-zero card equipped with a battery (hat). 

____

## Contact

laurent.fournier@adox.io

