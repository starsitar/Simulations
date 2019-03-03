#%% Change working directory from the workspace root to the ipynb file location. Turn this addition off with the DataScience.changeDirOnImportExport setting
import os
try:
	os.chdir(os.path.join(os.getcwd(), 'Simulations'))
	print(os.getcwd())
except:
	pass
#%% [markdown]
# **Study Objectives**
# 
# The study seeks to answer the following questions:
# 1. What is the impact of the shape of the token distribution on the shape of the final group ticket distribution?
# 2. What is the Likelihood of a >51% group ownership?
# 3. Is the SHA256# truly uniformly distributed
# 
# We attempt to answer these questions in the following ways:
# * We use a uniformly distributed set of ticket random numbers (assuming the SHA256 is uniformly distributed) and assign ownership based on several different ticket distributions, and then select a subset of minimum value into a "group"
# * We assume that if the shape of the ticket distribution in the group over several runs is similar to the distribution of ticket ownership it proves that the ticket ownership distribution has an impact on the final group
# * We guage the extent of the impact by determining the maximum percentage ownership of a group with respect to the maximum ticket ownership
# * We estimate the likelihood of >51% ownership by counting the number of times such a level is achieved in multiple runs.
# 
# What-If analysis for the following Token distributions:
# * Linear - max 10%,25%, 40%
# * Stepped - max 10%, 25%, 40%
#%% [markdown]
# **Ticket Generation and Threshold selection**
# We use numpy's random function to generate a uniform distribution of tickets. We then iteratively determine the min threshold required for the specified group size. 

#%%
GroupSize = 100
Runs = 10
Tickets = np.random.random_sample(int(total_tickets))


#%%



