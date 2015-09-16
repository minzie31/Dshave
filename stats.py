'''
Created on Sep 14, 2015

@author: joey
'''
import re
import time
from optparse import OptionParser

class Stats:
    """
    Lets you to parse an nginx log file of a given format. It parses using regular expressions and calculates stats like
    the count of 200-599 HTTP return codes. In case there is 50X return code it also mines of the route to the resource that 
    caused it. 
    """
    def __init__(self):
        self.tsAndProto = r'\[[0-9][0-9]/[A-Z][a-z][a-z]/[0-9|:]+ +\+[0-9]+\] +https? https? https?'
        self.tsAndProto2 = r'\[[0-9][0-9]/[A-Z][a-z][a-z]/[0-9|:]+ +\+[0-9]+\] +https? https?,https? https?,https? h?t?t?p?s? *'
        self.urlAndStatusCode = r'"[A-Z]+ (/.*) .+" ([2-5][0-9][0-9])'
        self.blankLine = r'^\s*$'
        self.form = '{code}:{count}|s\n'
        
    
    def extractPattern(self, line):
        """
        Returns a tuple that contains the HTTP route and return code
        :type line: string
        :param line: A single line from log file 
        """
        if re.search(self.tsAndProto, line):
            x = re.split(self.tsAndProto, line)
            return self.extractGroups(x[1])
            
        elif re.search(self.tsAndProto2, line):
            x = re.split(self.tsAndProto2, line)
            return self.extractGroups(x[1])
        elif re.match(r'^\s*$', line):
            return None
        else:
            print 'BAD PARSING ERROR. Did format change\n%s' % line
            #raise Exception('In case you want to be more strict about format')
            return None
              
    
    def mine(self, contents):
        """
        Returns a list of tuples list where each element is 
        tuple consisting of route and return code
        :type contents: string
        :param contents: contents what was read in the last 5 seconds 
        """
        results = map(lambda line:self.extractPattern(line), contents)
        return results

    def analyze(self, results):
        """
        Returns a dictionary of return codes mapping to counts and 
        resource urls mapping to counts 
        :type results: list of tuples
        :param results: list where each element is tuple consisting of route and return code
        """
        ##Dictionary of lambdas pointing to file format codes
        lambdas = {
            lambda x: x.startswith('5'):'50x',
            lambda x: x.startswith('4'):'40x',
            lambda x: x.startswith('3'):'30x',
            lambda x: x.startswith('2'):'20x'
        }
        ##Dictionary of file format codes pointing to their count
        ##Also routes returing 50X pointing to how many times they were accessed 
        codeRoutes = {
                  '50x':0,
                  '40x':0,
                  '30x':0,
                  '20x':0, 
                    }
        fresults = filter(lambda x: not x == None, results)
        for result in fresults:
            route, code = result
            matches = filter(lambda f:f(code), lambdas.keys())
            if not len(matches) == 0:
                codePattern = lambdas[matches[0]]
                codeRoutes[codePattern] += 1
                if codePattern == '50x':
                    codeRoutes[route] = codeRoutes[route] + 1 if route in codeRoutes else 1
        return codeRoutes
    
    
    def pretty_print(self, codeRoutes):
        """
        Returns a string that contains the analyzed data based on format
        :type codeRoutes: dict
        :param codeRoutes: a dictionary of return codes mapping to counts and 
        resource urls mapping to counts
        """
        pretty = reduce(lambda res,item: res + 
                    self.form.format(code=item, 
                    count=codeRoutes[item]), 
                    codeRoutes.keys(), '')
       
        return pretty
    
    def extractGroups(self, substr):
        return re.search(self.urlAndStatusCode, substr).group(1, 2)
         
def watch(logfile, outfp, stat):
    """
    Watches the nginx log file for every 5 seconds
    :type logfile: string
    :param logfile: The location of the nginx log file
    Default: There is no default value.

    :type outfp: file object
    :param outfp: File object that points to location of stats.log
    :type stat: Stats object
    :param stat: 
    """
    while True:
        lines = logfile.readlines()
        if not lines:
            time.sleep(5)
            continue
        yield lines

            
if __name__ == '__main__':
    usage = 'usage: %prog <OPTIONS>'
    parser = OptionParser(usage=usage)
    parser.add_option('-l', '--logfile', dest='logfile', default='/var/log/nginx/access.log',
                  help='Nginx log file location')
    parser.add_option('-s', '--statsfile', dest='statsfile', default='/var/log/stats.log',
                  help='Stats file location')
    arg_map, leftovers = parser.parse_args()
    logfile = arg_map.logfile
    statsfile = arg_map.statsfile
    fp = open(logfile, 'r')
    outfp = open(statsfile, 'a')
    stat = Stats()
    lines = watch(fp, outfp, stat)
    for line in lines:
        results = stat.mine(line)
        codeRoutes = stat.analyze(results)
        print codeRoutes
        pretty = stat.pretty_print(codeRoutes)
        outfp.write(pretty)
        outfp.flush()
        
    fp.close()
    outfp.close()


    

