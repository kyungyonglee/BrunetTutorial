
using System;
using System.Security.Cryptography;

/**
 * Simple Brunet program that starts a node and potentially
 * connects to other nodes.
 * 
 * Compile this code with:
 * gmcs SNodeExample.cs -r:Brunet.dll
 * 
 * you should make a copy of Brunet.dll into the local directory,
 * so the program can use the Brunet library.
 * 
 * Should be helpful for people who want to create applications
 * which use Brunet
 *
 * This Node is a StructuredNode, it only lives on the Structured system.
 *
 * You can do basically the same thing with a HybridNode.
 */
public class SNodeExample {

  public static int Main(string[] args) {

    /**
     * Get the arguments
     */
    if( args.Length < 2 ) {
      Console.Error.WriteLine("usage: SNodeExample.exe [tcp|udp] port remota_ta0 remote_ta1 ...");
      return 0;
    }

    /**
     * Make the edge listener:
     */
    Brunet.EdgeListener el = null;
    int port = Int32.Parse( args[1] );
    if( args[0].ToLower() == "tcp" ) {
      el = new Brunet.TcpEdgeListener(port);
    }
    else if( args[0].ToLower() == "udp" ) {
      el = new Brunet.UdpEdgeListener(port);
    }
    /**
     * Create a random address for our node.
     * Some other application might want to select the address
     * a particular way, or reuse a previously selected random
     * address.  If the addresses are not random (or the output
     * of secure hashes) the network might not behave correctly.
     */
    RandomNumberGenerator rng = new RNGCryptoServiceProvider();
    Brunet.AHAddress tmp_add = new Brunet.AHAddress(rng);
    /**
     * Make the node that lives in a particular
     * namespace (or realm) called "testspace"
     */
    Brunet.Node tmp_node = new Brunet.StructuredNode(tmp_add, "testspace");
    /**
     * Add the EdgeListener
     */
    tmp_node.AddEdgeListener( el );
    /**
     * Tell the node who it can connect to:
     */
    for(int i = 2; i < args.Length; i++) {
      tmp_node.RemoteTAs.Add( Brunet.TransportAddressFactory.CreateInstance( args[i] ) );
    }
    /**
     * Now we connect, this blocks until Disconnect is called (in some
     * other thread or by some IDataHandler subscribed (see below).
     *
     * If you want to start Connect in its own thread do:
     * System.Threading.Thread t = new System.Threading.Thread(
     *    delegate() { tmp_node.Connect(); } );
     * t.Start();
     */
    tmp_node.Connect();
    
    /**
     * In a real application, we would create some IDataHandler 
     * objects and do:
     * tmp_node.GetTypeSource(PType...).Subscribe(my_handler, my_state)
     *
     * Then we can send some packets using AHSender, AHExactSender, etc...
     */
	 
    return 1;
  }
	
}
