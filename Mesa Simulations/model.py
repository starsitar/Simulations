from mesa import Model
from mesa.time import SimultaneousActivation
import agent
import numpy as np
from mesa.datacollection import DataCollector
import logging as log
import numpy as np
import random as rnd
import time

class Beacon_Model(Model):
    """The model"""
    def __init__(self, nodes, ticket_distribution, active_group_threshold, 
    group_size, max_malicious_threshold_percent, group_expiry, 
    node_failure_percent, node_death_percent,
    signature_delay, min_nodes, node_connection_delay, node_mainloop_connection_delay, 
    log_filename, run_number, dkg_block_delay, compromised_threshold,
    failed_signature_threshold, node_ownership_params, min_stake_amount, owner_mode):
        self.num_nodes = nodes
        self.schedule = SimultaneousActivation(self)
        self.relay_request = False
        self.active_groups = {}
        self.num_active_groups = 0
        self.active_nodes = {}
        self.num_active_nodes = 0
        self.inactive_nodes = []
        self.active_group_threshold = active_group_threshold # number of groups that will always be maintained in an active state
        self.max_malicious_threshold_percent = max_malicious_threshold_percent # threshold above which a signature is deemed to be compromised, typically 51%
        self.group_size = group_size
        self.ticket_distribution = ticket_distribution
        self.newest_id = 0 #ID count for agents
        self.group_expiry = group_expiry
        self.bootstrap_complete = False # indicates when the initial active group list bootstrap is complete
        self.group_formation_threshold = min_nodes # min nodes required to form a group
        self.timer = 0
        self.unsuccessful_signature_events = []
        self.signature_delay = signature_delay
        self.dkg_block_delay = dkg_block_delay
        self.compromised_threshold = compromised_threshold
        self.median_malicious_group_percents = 0
        self.median_dominated_signatures_percents = 0
        self.perc_dominated_signatures = 0
        self.perc_compromised_groups = 0
        self.total_signatures = 0
        self.failed_signature_threshold = failed_signature_threshold
        self.perc_failed_signatures = 0
        self.number_of_owners = len(ticket_distribution)
        self.min_stake_amount = min_stake_amount
        self.datacollector = DataCollector(
            model_reporters = {"# of Active Groups":"num_active_groups",
             "# of Active Nodes":"num_active_nodes",
             "# of Signatures":"total_signatures",
             "Median Malicious Group %": "median_malicious_group_percents",
             "% Compromised Groups": "perc_compromised_groups",
             "Median Dominator %":"median_dominated_signatures_percents",
             "% Dominated signatures":"perc_dominated_signatures",
             "Failed Singature %" : "perc_failed_signatures" },
            agent_reporters={"ID": "id" , 
            "Type" : "type",
            "Node Status (Connection_Mainloop_Stake)": lambda x : str(x.connection_status) if x.type == "node" else None,
            "Status": lambda x: x.status if x.type == "group" or x.type == "signature" else None, 
            "Malicious": lambda x : x.malicious if x.type == "node" else None,
            "DKG Block Delay" : lambda x : x.dkg_block_delay if x.type =="group" else None,
            "Ownership Distribution" : lambda x : x.ownership_distr if x.type =="group" or x.type == "signature" else None,
            "Malicious %" : lambda x : x.malicious_percent if x.type == "group" else None,
            "Offline %" : lambda x : x.offline_percent if x.type == "group" or x.type == "signature" else None,
            "Dominator %": lambda x : x.dominator_percent if x.type == "signature" else None,
            "Owner": lambda x : x.node_owner if x.type == "node" else None})

        #create log file
        log.basicConfig(filename=log_filename + str(run_number), filemode='w', format='%(name)s - %(levelname)s - %(message)s')
        self.log = log

        print("creating nodes")
        #create nodes
        if owner_mode = 1: # owners nodes are proportional to its total stake amt
            for i in range(self.number_of_owners): 
                total_owner_nodes = math.floor(self.ticket_distribution[i]/self.min_stake_amount)
                tickets = min_stake_amount
                    for j in range(total_owner_nodes)
                    node = agent.Node(self.newest_id, self, 
                    tickets, 
                    node_failure_percent, 
                    node_death_percent, 
                    node_connection_delay, 
                    node_mainloop_connection_delay
                    )
                    self.schedule.add(node)
        elif owner_mode = 2: # 1 node per owner
            for i in range(self.number_of_owners): 
                tickets = self.ticket_distribution[i]
                node = agent.Node(self.newest_id, self, 
                tickets, 
                node_failure_percent, 
                node_death_percent, 
                node_connection_delay, 
                node_mainloop_connection_delay
                )
                self.schedule.add(node)



    def step(self):
        '''Advance the model by one step'''
 
        log.debug("Number of nodes in the forked state = " + str(len(self.active_nodes)))

        #bootstrap active groups as nodes become available. Can only happen once enough nodes are online
        if self.bootstrap_complete == False:
            log.debug("bootstrapping active groups")
            if len(self.active_nodes)>=self.group_formation_threshold:
                for i in range(self.active_group_threshold):
                    new_group = self.group_registration()
                    self.active_groups[new_group.id] = new_group
                self.bootstrap_complete = True
        
        #generate relay requests
        self.relay_request = np.random.choice([True,False]) # make this variable so it can be what-if'd
        log.debug("relay request recieved? = "+ str(self.relay_request))

        if self.relay_request:
            try:
                log.debug('     selecting group at random')
                # pick an active group from the active group list and create a signature object
                signature = agent.Signature(self.newest_id, self, self.active_groups[rnd.choice(list(self.active_groups))]) 
            
                self.schedule.add(signature)
            except:
                log.debug('     no active groups available')

            log.debug('     registering new group')
            self.group_registration()
        else:
            log.debug("     No relay request")
        self.timer += 1

        #calculate model measurements
        self.calculate_compromised_groups()
        self.calculate_dominated_signatures()
        
        #advance the agents
        self.schedule.step()
        self.num_active_nodes = len(self.active_nodes)
        self.num_active_groups = len(self.active_groups)
        self.datacollector.collect(self)

    def group_registration(self):
        ticket_list = {}
        group_members = []

        if len(self.active_nodes)<self.group_formation_threshold: 
            log.debug("             Not enough nodes to register a group")

        else:
            # make each active node generate tickets and save them to a list
            counter = 0
            for node_id in self.active_nodes:
                counter +=0.00000001
                self.active_nodes[node_id].generate_tickets()
                # converts the list to a dict with key value as the ticket number + counter and value as node id
                # adding a counter helps take care of repeated keys
                temp_ticket_dict = {i : node_id for i in (self.active_nodes[node_id].ticket_list + counter)}
                ticket_list.update(temp_ticket_dict)
            
            # sort the dict and pick n smallest values 
            group_list = sorted(ticket_list.items())[0:self.group_size]

            # add create the list of member nodes
            for node_id in group_list:
                group_members.append(self.active_nodes[node_id[1]])
            
            #create a group agent which can track expiry, sign, etc
            group_object = agent.Group(self.newest_id, self, group_members, self.group_expiry)


            #add group to schedule
            self.schedule.add(group_object)

            #add group to active group list
            self.active_groups[group_object.id] = group_object
            
            return group_object

    def refresh_active_group_list(self):
        temp_list = {}

        for group in self.schedule.agents:
            if group.type == "group":
                if group.status == "active":
                    temp_list[group.id] = group
        self.active_groups = temp_list

    def refresh_connected_nodes_list(self):
        log.debug("refreshing active nodes list")
        temp_active_node_list = {}
        temp_inactive_node_list = {}
        for agent in self.schedule.agents:
            if agent.type == "node":
                if agent.connection_status == "connected": 
                    temp_active_node_list[agent.id] = agent #adds the node to the active list only if it is in the connected
                
                else:
                    temp_inactive_node_list[agent.id] = agent
        self.active_nodes = temp_active_node_list
        self.inactive_nodes = temp_inactive_node_list
        print(self.active_nodes)

    def calculate_compromised_groups(self):
    #Calculate compromised groups
        malicious_array = []
        total_groups = 0
        for group in self.schedule.agents:
            if group.type == "group":
                total_groups +=1
                malicious_array.append(group.malicious_percent) #creates an array of malicious percents for each group
        print(malicious_array)
        self.median_malicious_group_percents = np.median(malicious_array)
        self.perc_compromised_groups = sum(np.array(malicious_array)>=self.compromised_threshold)/(total_groups+0.000000000000000001)

    def calculate_dominated_signatures(self):
        dominator_array = []
        dominator_count = 0
        total_signatures = 0
        failed_signatures = 0
        for signature in self.schedule.agents:
            if signature.type == "signature":
                total_signatures +=1
                dominator_array.append(signature.dominator_percent)
                dominator_count += (signature.dominator_percent>=self.max_malicious_threshold_percent)
                failed_signatures += (signature.offline_percent>=self.failed_signature_threshold)

        self.perc_failed_signatures = failed_signatures/(total_signatures+0.00000000000000001)
        self.median_dominated_signatures_percents = np.median(dominator_array)
        self.perc_dominated_signatures = dominator_count/(total_signatures+0.00000000000000001)
        self.total_signatures = total_signatures


def create_cdf(nodes,ticket_distr):
# Create CDF's - used to determine max ownership ticket index
    cdf = np.zeros(nodes)
    for node,ticketmax in enumerate(ticket_distr):
        
        cdf[node]=sum(ticket_distr[0:node+1])
    return cdf



            
            





    










        

        







