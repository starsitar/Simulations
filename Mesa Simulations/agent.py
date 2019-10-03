from mesa import Agent, Model
from mesa.time import RandomActivation
import numpy as np
import math

class Node(Agent):
    """ Node: One hardware device used to stake tokens on the network. 
    Each node will create virtual stakers proportional to
    the number of tokens owned by the node """
    def __init__(self, unique_id, node_id, model, tickets, 
    failure_percent, death_percent, node_connection_delay,
    node_mainloop_connection_delay, misbehaving_nodes):
        super().__init__(unique_id, model)
        self.id = unique_id
        self.type = "node"
        self.node_id = node_id
        self.num_tickets = int(tickets)
        self.ticket_list = []
        self.connection_status = "not connected" #change later to event - currently used for node failure process
        self.connection_delay = np.random.randint(0,node_connection_delay) #uniform randomly assigned connection delay step value
        self.timer = self.model.timer
        self.node_connection_failure_percent = failure_percent
        self.node_death_percent = death_percent
        self.connection_failure = False
        self.death = False
        self.node_owner = int((np.random.normal(self.model.node_ownership_params[0], self.model.node_ownership_params[1])+3.5)*15) # picks an owner using the normal distribution and parameters set in the sim
        self.malicious = self.model.owner_buckets[math.ceil(self.node_owner/10)] # sets the node as malicious if its owner is malicious

    def step(self):
        #simulate node failure
        self.connection_failure = np.random.randint(0,100) < self.node_connection_failure_percent
        self.death = np.random.randint (0,100) < self.node_death_percent

        #disconnect the node if failure occurs
        if (self.connection_failure or self.death) and self.connection_status == "connected":
            self.node_disconnect()
        else:
            if self.connection_delay>0:
                self.connection_delay -=1
            else:
                self.connection_status = "connected"
                self.model.active_nodes[self.id] = self # add to the active nodes list
                

    def advance(self):
        pass


    def generate_tickets(self):
        #generates tickets using the uniform distribution
        self.ticket_list = np.random.random_sample(self.num_tickets)
        
    def node_disconnect(self):
        # disconnect the node from the network; causes it to go through the entire reconnection sequence in the next step
        self.connection_status = "not connected"
        try:
            self.model.active_nodes.pop(self.id) # remove from the active nodes list
        except: self.model.log.debug("node not in active list")

        if self.death == False: # does not reset the failure trigger if the death trigger is true
            self.failure = False

class Group(Agent):
    """ A Group """
    def __init__(self, unique_id, model, members, expiry):
        super().__init__(unique_id, model)
        self.id = unique_id
        self.type = "group"
        self.members = members
        self.status = "dkg" # status types: dkg, compromised, active, expired
        self.expiry = expiry # of steps before expiration
        self.timer = self.model.timer
        self.model.newest_id +=1
        self.ownership_distr = []
        self.malicious_percent = 0
        self.offline_percent = 0
        self.compromised_percent = 0
        self.process_complete = False
        self.dkg_block_delay = self.model.dkg_block_delay

        self.calculate_ownership_distr()


    def step(self):
        """ block delay to simulate the multiple DKG steps"""
        if self.status == "dkg":
            if self.dkg_block_delay>=0:
                self.dkg_block_delay -=1 # counts down the block delay
                # based on DKG process we check for missing/malicious nodes 3 blocks before dkg completes
                if self.dkg_block_delay == 3:
                    self.offline_percent = self.calculate_offline()/len(self.members) # calculates % nodes offline during dkg
                    self.compromised_percent = self.malicious_percent #+ self.offline_percent
            else:
                self.status = "active"
                self.model.active_groups[self.id] = self # add to active groups list
        elif self.status == "active":
            """ At each step check if the group has expired """
            self.expiry -=1
            if self.expiry <= 0: 
                self.status = "expired"
                try:
                    self.model.active_groups.pop(self.id)
                except: self.model.log.debug("group not in active list")

        
    def advance(self):
        pass

    def calculate_ownership_distr(self):
        temp_distr = np.zeros(self.model.num_nodes)
        temp_malicious_count = 0
        for node in self.members:    
            temp_distr[node.node_id] +=1 # increments by 1 for each node index everytime it exists in the member list, at each step
            if node.malicious:
                temp_malicious_count +=1
        self.malicious_percent = temp_malicious_count/sum(temp_distr)
        self.ownership_distr = temp_distr


    def calculate_offline(self):
        offline_count = 0
        for node in self.members:
            if node.connection_status == "not connected": 
                offline_count +=1
        return offline_count
    
class Signature(Agent):
    def __init__(self, unique_id, model, group_object):
        super().__init__(unique_id, model)
        self.group = group_object
        self.id = unique_id
        self.type = "signature"
        self.status = "started"
        self.delay = np.random.poisson(self.model.signature_delay) #delay between when it is triggered and when it hits the chain
        self.ownership_distr = []
        self.model.newest_id +=1 # increments the model agent ID by 1 after a new signature is created 
        self.signature_process_complete = False
        self.block_delay_complete = False
        self.dominator_percent = 0
        self.offline_percent = 0
        self.owner_lynchpin_percent = 0

    def step(self):
        #signature
        if not self.block_delay_complete:
            if self.delay >0:
                self.delay -=1
            else :
                self.block_delay_complete = True
        elif not self.signature_process_complete :
            self.signature_process()
            self.signature_process_complete = True
            self.status = "complete"

    def advance(self):
        pass

    def signature_process(self):
        # Calculates ownership data just before the signature is complete
        temp_signature_distr = np.zeros(self.model.num_nodes)

        for node_id,node_tickets in enumerate(self.group.ownership_distr): # checks if the node has a non-zero ownership, i is the node id
            if node_tickets > 0:
                if node_id in self.model.active_nodes:
                    temp_signature_distr[node_id] = node_tickets
        self.ownership_distr = temp_signature_distr
        failed_list = np.array(self.group.ownership_distr)-np.array(self.ownership_distr)
        self.offline_percent = sum(failed_list)/sum(self.group.ownership_distr)
        self.dominator_percent = (sum(failed_list) + max(self.ownership_distr))/sum(self.group.ownership_distr) # adds the failed node virtual stakers and max node virtual stakers
        
        #Calculate lynchpin owner
        shares_by_staker = {}
        total_tickets = sum(self.ownership_distr)
        for node_id,node_tickets in enumerate(self.ownership_distr):
            if node_id in self.model.active_nodes:
                try:
                    shares_by_staker[self.model.active_nodes[node_id].node_owner]+=node_tickets #add tickets to owner shares
                except:
                    shares_by_staker.update({self.model.active_nodes[node_id].node_owner : node_tickets})
                    
        self.owner_lynchpin_percent = shares_by_staker[max(shares_by_staker)]/total_tickets

    





        

