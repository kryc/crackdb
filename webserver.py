from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from cgi import parse_header, parse_multipart
from urllib.parse import parse_qs
import json
import binascii
import crackdb


MAIN_PAGE = '''
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <meta name="description" content="">
    <meta name="author" content="">

    <title>Hash Cracker WebUI</title>
</head>
<body>

    <div class="container">
        <div class="header clearfix">
            <h3 class="text-muted">HashCracker WebUI</h3>
        </div>
        <div class="container">
            <p> Enter a new line separated list of hashes in the box and click Crack!</p>
            <textarea id="hashes" style="width:100%; height:400px"></textarea><br/>
            <p>Currently supported hashes: {:s}</p><br/>
            <a class="btn btn-lg btn-success" href="#" role="button" id="crack">Crack!</a>
            <a class="btn btn-lg btn-success" href="#" role="button" id="clear">Clear</a>
        </div>
        <div class="container" id="resultssection" style="display:none">
            <table id="results" class="table table-hover">
                <thead>
                    <tr><th>Hash</th><th>Algorithm</th><th>Password</th></tr>
                </thead>
                <tbody>
                </tbody>
            </table>
        </div>
    </div>
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css">
    <script src="https://code.jquery.com/jquery-3.2.1.min.js"></script>
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js"></script>
    <script src="crackdb.js"></script>
</body>
</html>
'''

JAVASCRIPT = '''
$("#crack").click(function(){
    $.post('docrack.asp',
        {
            hashes: JSON.stringify($("textarea#hashes").val().split(/[\\r\\n]+/))
        },
        function(data, status){
            var results = JSON.parse(data);
            for (var i=0; i<results.length; i++){
                var newrow = document.createElement('tr');
                var newcell = document.createElement('td');
                newcell.appendChild(document.createTextNode(results[i][0]));
                newrow.appendChild(newcell);
                newcell = document.createElement('td');
                newcell.appendChild(document.createTextNode(results[i][1]));
                newrow.appendChild(newcell);
                newcell = document.createElement('td');
                newcell.appendChild(document.createTextNode(results[i][2]));
                newrow.appendChild(newcell);
                $("#results").find('tbody')
                    .append(newrow);
            }
            $("textarea#hashes").val('');
            $("#resultssection").show();
        });
    });
$("#clear").click(function(){
     $("#results tbody tr").remove();
     $("#resultssection").hide();
    });
'''

class Handler(BaseHTTPRequestHandler):

    def do_GET(self):
        '''
        Override the default GET handler
        We respond to any request to the root URI with the
        main HTML page and any URI ending with '.js' with
        our custom javascript
        '''
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(MAIN_PAGE.format(', '.join(crackdb.getAlgorithms(LOCATION))))
        elif self.path.endswith('.js'):
            self.send_response(200)
            self.send_header('Content-type', 'application/javascript')
            self.end_headers()
            self.wfile.write(JAVASCRIPT)
        return

    def parse_POST(self):
        '''
        Utility function to pull out the post variables
        from the HTTP body
        '''
        ctype, pdict = parse_header(self.headers['content-type'])
        if ctype == 'multipart/form-data':
            postvars = parse_multipart(self.rfile, pdict)
        elif ctype == 'application/x-www-form-urlencoded':
            length = int(self.headers['content-length'])
            postvars = parse_qs(self.rfile.read(length), 
                                keep_blank_values=1)
        else:
            postvars = {}
        return postvars

    def do_POST(self):
        '''
        Override the default POST handler
        The web interface sends a json array of hex encoded hash strings
        We docode these and pass them straight through to the cracker
        '''
        self.send_response(200)
        self.end_headers()
        postvars = self.parse_POST()
        hashes = json.loads(postvars['hashes'][0])
        results = []
        for hashstr in hashes:
            # Do the crack
            available = crackdb.getAlgorithms(LOCATION)
            result = crackdb.lookup(LOCATION, binascii.unhexlify(hashstr), available)
            algorithm, word = ('', 'UNKNOWN', ) if result == None else result
            results.append((hashstr, algorithm, word, ))
            print(json.dumps(results))
        self.wfile.write(json.dumps(results))
        return

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""

LOCATION = '.'

def startServer(location, address='0.0.0.0', port=8080):
    '''
    The main function for starting the web server
    This is called directly from within the main crackdb.py
    '''
    global LOCATION
    server = ThreadedHTTPServer((address, port), Handler)
    print('Starting server, use <Ctrl-C> to stop')
    LOCATION = location
    server.serve_forever()
