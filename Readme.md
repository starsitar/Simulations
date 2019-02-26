Simple Relay Simulation

blssim.py
Description: 
The simulation runs multiple experiments. 
Each experiment consists of a relay run until the failure criteria is met. 
On each relay run, an array of failure probabilities is generated, with each index of the array corresponding to a group in the relay
A group is randomly selected using the numpy random number generator
The failure probability is checked and the run is terminated if it meets the failure criteria

A loop is used to run many experiments and an the estimate of the mean signatures before failure is shown


NodeStates.py
Description:
Simulation of node states within the threshold relay
