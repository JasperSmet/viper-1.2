from viper.common.abstracts import Module
from viper.core.session import __sessions__
from viper.core.storage import get_sample_path
from irmacl.helpers import *
import json

class Irma(Module):
    cmd = 'irma'
    description = 'Scan files through Irma framework'
    authors = ['Jasper Smet']

    def __init__(self):
        super(Irma, self).__init__()
        self.parser.add_argument('-e', '--engines', action='store_true', help='List engines')
        self.parser.add_argument('-s', '--scan', action='store_true', help='Scan file')
        self.parser.add_argument('-ls', '--list_scans', action='store_true', help='List scans')
        self.parser.add_argument('-f', '--find', action='store', help='find files')

        self.files = []


    def run(self):
    	super(Irma, self).run()


        if self.args:
            if self.args.engines:
                self.show_engines()
            if self.args.list_scans:
                self.show_scans()
            if self.args.find:
                self.find(self.args.find)
            elif self.args.scan:
                if not __sessions__.find:
                    self.log('error', "No find result")
                    return
                self.files = self.get_files_from_last_find()
            else:
                if not __sessions__.is_set():
                    self.log('error', "No session opened")
                    return
                self.files = self.get_file_from_current_session()
            if self.files:
                summary = self.show_analyzed_info(self.files[0][0])
                #self.show_summary(summary)
                return


    def get_files_from_last_find(self):
        files = []
        if __sessions__.find:
            for item in __sessions__.find:
                path = get_sample_path(item.sha256)
                files.append((path, item.name))
        return files

    def get_file_from_current_session(self):
        curr = __sessions__.current
        return [(curr.file.path, curr.file.name)]

    def show_analyzed_info(self,data):
        scan = scan_files([data], force=True, blocking=True)
        jsonresult = json.loads(json.dumps(scan.results[0].__dict__))
        probeResult = scan_proberesults(jsonresult["result_id"])
        for res in probeResult.probe_results:
            
            print(res)

    def show_scans(self):
        scanList = scan_list()
        print(scanList)

    def find(self, term):
         (total, res) = file_search(name=term)
         print(len(res))


    def show_engines(self):
        engines = probe_list()

       	if len(engines) == 0:
       		print("no engines active")
       	else:
            print("active scanengines")

       	    for eng in engines:
       			print eng
