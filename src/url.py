# Stores URL information into an object

class URL:
    def __init__(self, user_entry="", domain_name="", comodo_valkyrie_verdict="", created_date="", registrar="",
                 rank_majestic="", rank_statvo="", forcepoint_threatseaker="", undetected=0, malicious=0, engines="", results=""):

        self.user_entry = user_entry                            # string
        self.domain_name = domain_name                          # string
        self.comodo_valkyrie_verdict = comodo_valkyrie_verdict  # string
        self.created_date = created_date                        # string
        self.registrar = registrar                              # string
        self.rank_majestic = rank_majestic                      # integer
        self.rank_statvo = rank_statvo                          # integer
        self.forcepoint_threatseaker = forcepoint_threatseaker  # string
        self.total_undetected = undetected                      # integer
        self.total_malicious = malicious                        # integer
        self.engines = engines                                  # array of strings (same implementation as for hash)
        self.engine_results = results                           # array of strings (same implementation as for hash)

    # Function for transferring engine array into a comma delimited string
    def set_engines(self, engines):
        self.engines = ','.join(engines)

    # Function for transferring results array into a comma delimited string
    def set_results(self, results):
        self.engine_results = ','.join(results)

    # Returns the engines as an array
    def get_engines(self):
        return self.engines.split(',')

    # Returns the results as an array
    def get_results(self):
        return self.engine_results.split(',')
