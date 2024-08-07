/*=====================================================================*/
/*    .../prgm/project/hop/hop/test/hopjs/serv/aux/stressClient.js     */
/*    -------------------------------------------------------------    */
/*    Author      :  Vincent Prunet                                    */
/*    Creation    :  Mon Sep  14 11:43:00 2015                         */
/*    Last change :  Mon Jul 15 13:16:53 2024 (serrano)                */
/*    Copyright   :  2015-24 Inria                                     */
/*    -------------------------------------------------------------    */
/*    Stress test for services: client worker                          */
/*=====================================================================*/

/* This worker iterates service invocations for <numCalls> times, then
 * post a message to inform the main thread of completion */

var hop = require('hop');

service toTest();

var numCalls = 10;
//var numCalls = 20000;
var effectiveCalls = 0;

onmessage = function(e) {
   var id = e.data;
   test(id);
};

function test(id) {
   console.log("test, id=" + id + " calls=" + effectiveCalls + "/" + numCalls);
   if (effectiveCalls == numCalls) {
      postMessage(id);
   } else {
      try {
	 toTest({ id: id }).post(function(result) {
	    effectiveCalls++;
	    test(id);
	 }, { fail: function(error) {
	    console.log('Service invocation failed for client %s at %s',
			 id, effectiveCalls, error);
	    postMessage(id);
	 }});
      } catch(e) {
	 console.log('client %s cannot post at %s', id, effectiveCalls);
      }
   };
}
