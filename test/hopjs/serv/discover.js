"use hopscript";

const assert = require('assert');
const remote = new Worker('./aux/discoverServer.js');
const remoteServer = new hop.Server('localhost');

assert.ok(remoteServer instanceof hop.Server);

const localServer = new hop.Server('localhost');
assert.ok(localServer instanceof hop.Server);

localServer.foo = service() {
   console.log('foo');
};

remote.onmessage = function(message) {
   const remoteServer = message.data;
   console.log('client: server worker running');
  // remoteServer.register = service register(); // comment out when fixed.

   remoteServer.register(localServer)
      .post(
	 function(server) {
	    const s = { __proto__: server };
	    console.log('client: registration ok');
	    server.addSvc(11).post(
	       function(result) {
		  server.count().post(
		     function(value) {
			assert.equal(value, 11);
			console.log('test ok');
			process.exit(0);
		     },
		     function(error) {
			console.log('client: service count failed');
			process.exit(1);
		     }
		 );
	       },
	       function(error) {
		  console.log('client: service addSvc failed', error);
	       }
	   )
	 },
	 function(error) {
	    console.log('client: register failed');
	    process.exit(1);
	 }
     );
};

setTimeout(function() {
   console.log('timeout');
   process.exit(1);
}, 4000);
	    
	    
