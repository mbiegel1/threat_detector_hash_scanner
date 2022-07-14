# Stores file information into a file object
class File:

    def __init__(self, md5_hash="", sha256_hash="", sha1_hash="", ssdeep_hash="", total_malicious=0,
                 total_undetected=0, is_malicious=0, size=0, engines="", results=""):

        self.md5_hash = md5_hash
        self.sha256_hash = sha256_hash
        self.sha1_hash = sha1_hash
        self.ssdeep_hash = ssdeep_hash
        self.total_malicious = total_malicious
        self.total_undetected = total_undetected
        self.is_malicious = is_malicious
        self.size = size
        self.engines = engines
        self.engine_results = results

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

