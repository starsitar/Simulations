from math import floor
import numpy as np
from scipy import stats



class Beacon_Analysis():
    """Analytical solutions for simulation questions"""
    def __init__(
            self,

            # number of virtual stakers in the network
            virtual_stakers,
            # fraction of the network controlled by the adversary
            adversary_power,

            # number of members in a group
            group_size,
            # threshold of the BLS signature:
            #   producing a signature requires `(max_malicious + 1)` shares
            #   and tolerates up to `max_malicious` malicious members
            max_malicious,

            # fraction of nodes that are offline at any given moment
            node_failure_probability,
            # fraction of nodes that succumb to attrition while group is active
            node_death_probability
    ):
        self.virtual_stakers = virtual_stakers
        self.malicious_virtual_stakers = floor(virtual_stakers * adversary_power)

        self.group_size = group_size
        self.max_malicious = max_malicious
        self.min_honest = max_malicious + 1

        self.p_failure = node_failure_probability
        self.p_death = node_death_probability


    def g_range(self):
        return np.arange(self.group_size + 1)


    def malicious_dist(self):
        nv = self.virtual_stakers
        mv = self.malicious_virtual_stakers
        g = self.group_size

        return stats.hypergeom(nv, mv, g)


    def malicious(self):
        dist = self.malicious_dist()

        return dist.pmf(self.g_range())


    def attrition(self):
        dist = stats.binom(self.group_size, self.p_death)

        return dist.pmf(self.g_range())


    def offline(self, g_remaining):
        dist = stats.binom(g_remaining, self.p_failure)

        gr_range = np.arange(g_remaining + 1)

        return dist.pmf(gr_range)


    def inactive(self):
        g = self.group_size

        # get the probability of n members being dead
        # for each 0 <= n <= group_size
        pmf_dead = self.attrition()

        # prepare array of inactivity probabilities
        pmf_inactive = np.zeros(g + 1)

        # for each possible number of dead members
        for n_dead in range(g + 1):
            g_remaining = g - n_dead

            # calculate the distribution of offline members
            pmf_offline = self.offline(g_remaining)

            # for each possible number of offline members
            for n_offline in range(g_remaining + 1):

                # calculate the cumulative probability of this combination
                # and add it to the probability mass array
                p_inactive = pmf_dead[n_dead] * pmf_offline[n_offline]
                pmf_inactive[n_dead + n_offline] += p_inactive

        return pmf_inactive


    def inactive_dist(self):
        # build a custom discrete distribution
        nk = self.g_range()
        pk = self.inactive()
        dist = stats.rv_discrete(name='inactive', values=(nk, pk))

        return dist


    def compromised(self):
        # A group is compromised if the number of malicious members
        # exceeds the maximum number of malicious members:
        #
        #     n_malicious > max_malicious
        #
        dist = self.malicious_dist()

        return dist.sf(self.max_malicious)


    def sigfail(self):
        # A signature cannot be produced if the number of online members
        # is less than the minimum number of honest members:
        #
        #     group_size - n_inactive < min_honest
        #     n_inactive > group_size - min_honest
        #
        dist = self.inactive_dist()

        return dist.sf(self.group_size - self.min_honest)


    def lynchpinned(self):
        # A group is lynchpinned if it can produce a signature,
        # but only with input from the malicious party.
        # This implies that the number of inactive members
        # is less than the critical value,
        # but if malicious members withdraw ther contribution,
        # the remaining members fall below the minimum honest number:
        #
        #     n_inactive <= group_size - min_honest
        #     (n_inactive + n_malicious) > group_size - min_honest
        #
        g = self.group_size
        h = self.min_honest

        t = g - h

        pmf_inactive = self.inactive()
        pmf_malicious = self.malicious()

        p_lynchpinned = 0

        # for a group to be lynchpinned,
        # the number of inactive members must be in [0, t]
        for n_inactive in range(0, t + 1):
            p_inactive = pmf_inactive[n_inactive]

            # with i inactive members,
            # the number of malicious members m must satisfy:
            #
            #     (i + m) in [t+1, g]
            for n_malicious in range(t - n_inactive + 1, g - n_inactive + 1):
                p_malicious = pmf_malicious[n_malicious]

                prob = p_inactive * p_malicious

                p_lynchpinned += prob

        return p_lynchpinned
