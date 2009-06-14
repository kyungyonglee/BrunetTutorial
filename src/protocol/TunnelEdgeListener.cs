
/*
This program is part of BruNet, a library for the creation of efficient overlay
networks.
Copyright (C) 2005  University of California
Copyright (C) 2007 P. Oscar Boykin <boykin@pobox.com>, Arijit Ganguly <aganguly@acis.ufl.edu>
University of Florida
This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
*/

using System;
using System.Net;
using System.Net.Sockets;
using System.Collections;
using System.IO;
using System.Threading;

namespace Brunet
{

  /**
   * This class implements the TunnelEdgeListener. Sometime due to NATs or some BGP 
   * outage, its possible two neighboring nodes in P2P cannot connect. In such a situation,
   * we create an edge that tunnel packets through some other P2P node. 
   */

  public class TunnelEdgeListener: EdgeListener, IDataHandler
  {
    /**
     * An Enumerable object of local TransportAddresses.
     */
    public override IEnumerable LocalTAs
    {
      get {
        return new TunnelTAEnumerable(_node);
      }
    }

    /**
     * This class returns an enumarable list of tunnel URIs for a node. 
     * However, it turns out that there is just one element in the list. 
     * Each time we do a GetEnumerator, we generate a fresh
     * TransportAddress with the latest information.
     */
    protected class TunnelTAEnumerable : IEnumerable {
      protected Node _node;
      public TunnelTAEnumerable(Node n) {
        _node = n;
      }

      /**
       * @returns an enumerator for the local tunnel TAs. 
       */
      public IEnumerator GetEnumerator() {
        ArrayList nearest = _node.ConnectionTable.GetNearestTo( (AHAddress) _node.Address, 6);
        ArrayList forwarders = new ArrayList();
        foreach(Connection cons in nearest) {
#if TUNNEL_DEBUG
          Console.Error.WriteLine("TunnelEdgeListener: testing if we can tunnel using node: {0}", cons.Address);
#endif
          if (cons.Edge.TAType != TransportAddress.TAType.Tunnel) {
            forwarders.Add(cons.Address);
#if TUNNEL_DEBUG
            Console.Error.WriteLine("TunnelEdgeListener: added node: {0} to tunnel TA", cons.Address);
#endif
          }
        }
        if (forwarders.Count >= MIN_FORWARDERS ) {
          TransportAddress tun_ta = new TunnelTransportAddress(_node.Address, forwarders);
#if TUNNEL_DEBUG
          Console.Error.WriteLine("TunnelEdgeListener: built tunnel TA: {0}", tun_ta);
#endif          
          yield return tun_ta;
        }
      }
    }

    // _id_ht is a mapping of ids to edges
    public override int Count { get { return _id_ht.Count; } }

      /**
       * Type of TransportAddress does this EdgeListener uses.
       */
    public override TransportAddress.TAType TAType
    {
      get {
        return TransportAddress.TAType.Tunnel;
      }
    }

    //all packet receiving happens through the node
    protected Node _node;

    /**
     *  Hashtable of ID to Edges
     */
    protected Hashtable _id_ht;
    protected Hashtable _remote_id_ht;

    protected Random _rand;

    protected object _sync;
    
    protected int _running;
    protected int _isstarted;
    
    /*
     * Don't try to use TunnelEdge unless we have this many common neighbors.
     */
    protected const int MIN_FORWARDERS = 1;

    /**
     * @return true if the Start method has been called.
     */
    public override bool IsStarted
    {
      get {
        return _isstarted == 1;
      }
    }
    /**
     * Message types that are exchaged while creating, maintaining and using tunnel edges
     * for exchange of data. 
     */
    public enum MessageType:byte 
    {
      EdgeRequest,
      EdgeResponse,
      EdgeData,
      EdgeControl,
      EdgeSync,
    }

    /**
     * This method creates an instance of a tunnel edge to a remote node, given its 
     * tunnel transport URI.
     * @param ta TransportAddress to create an edge to
     * @param ecb the EdgeCreationCallback to call when done
     * @throw EdgeException if we try to call this before calling
     * Start.
     */
    public override void CreateEdgeTo(TransportAddress ta, EdgeCreationCallback ecb) 
    {
      try {
      if (!IsStarted) {
        throw new EdgeException("TunnelEdgeListener not started");
      }
      else if (0 == _running) {
        throw new EdgeException("TunnelEdgeListener not running");
      }
      else if (ta.TransportAddressType != this.TAType) {
	throw new EdgeException(ta.TransportAddressType.ToString()
				+ " is not my type: " + this.TAType.ToString());
      }
      else {
#if TUNNEL_DEBUG
        Console.Error.WriteLine("CreateEdgeTo TunnelEdge to: {0}", ta);
#endif  
        TunnelTransportAddress tun_ta = ta as TunnelTransportAddress;
        ArrayList forwarders = new ArrayList();
        ArrayList forwarding_edges = new ArrayList();
#if TUNNEL_DEBUG
        Console.Error.WriteLine("TunnelEdgeListener: Finding structured connections to tunnel over");
#endif
        IEnumerable struc_cons = _node.ConnectionTable.GetConnections(ConnectionType.Structured);
        if (struc_cons ==  null) {
#if TUNNEL_DEBUG
          Console.Error.WriteLine("List of structured connections is null");
#endif 
        }
#if TUNNEL_DEBUG
        Console.Error.WriteLine("TunnelEdgeListener: Browsing list of structured connections");
#endif
        foreach (Connection con in struc_cons) {
#if TUNNEL_DEBUG
          Console.Error.WriteLine("TunnelEdgeListener: Testing : {0}", con.Address);
#endif
          if (con.Edge.TAType == TransportAddress.TAType.Tunnel) {
#if TUNNEL_DEBUG
            Console.Error.WriteLine("Cannot tunnel over tunnel: " + con.Address.ToString());
#endif
            continue;
          }
          if (!tun_ta.ContainsForwarder(con.Address)) {
#if TUNNEL_DEBUG
            Console.Error.WriteLine("Cannot tunnel over connection: " + con.Address.ToString());
#endif
            continue;
          }
#if TUNNEL_DEBUG
          Console.Error.WriteLine("Can tunnel over connection: " + con.Address.ToString());
#endif
          forwarders.Add(con.Address);
          forwarding_edges.Add(con.Edge);
        }

        if (forwarders.Count < MIN_FORWARDERS) {
          ecb(false, null, new EdgeException("Cannot create edge over TA: " + tun_ta + ", not many forwarders"));
          return;
        }
        tun_ta = new TunnelTransportAddress(tun_ta.Target, forwarders);
        
        //choose a locally unique id
        lock( _sync ) {
          //Get a random ID for this edge:
          int localid;
          int remoteid = 0;
          do {
            localid = _rand.Next();
            //Make sure we don't have negative ids
            if( localid < 0 ) { localid = ~localid; }
          } while( _id_ht.Contains(localid) || localid == 0 );      
          //looks like the new edge is ready
          TunnelEdge e = new TunnelEdge(this, false, _node, tun_ta.Target, forwarders, localid, remoteid);
#if TUNNEL_DEBUG
          Console.Error.WriteLine("Creating an instance of TunnelEdge: {0}", e);
          Console.Error.WriteLine("remoteid: {0}, localid: {1}", remoteid, localid);
#endif      
          _id_ht[localid] = e;
          //we will defer the new edge event for later
          //when we actually get a response
          
          //now build the packet payload
          Packet p = null;
          using(MemoryStream ms = new MemoryStream()) {
            ms.WriteByte((byte) MessageType.EdgeRequest);
            NumberSerializer.WriteInt(localid, ms);
            NumberSerializer.WriteInt(remoteid, ms);
    #if TUNNEL_DEBUG
            Console.Error.WriteLine("Written off type, localid, remoteid");
    #endif
            
            ArrayList args = new ArrayList();
            //add the target address
            byte[] addr_bytes = new byte[Address.MemSize];
            _node.Address.CopyTo(addr_bytes);
            args.Add(addr_bytes.Clone());
    #if TUNNEL_DEBUG
            Console.Error.WriteLine("Added target address");
    #endif
            
            foreach (Address fwd in  forwarders) {
              //add forwarding addresses
              fwd.CopyTo(addr_bytes);
              args.Add(addr_bytes.Clone());
    #if TUNNEL_DEBUG
              Console.Error.WriteLine("Added a forwarding address");
    #endif
    
            }
    #if TUNNEL_DEBUG
            Console.Error.WriteLine("Creating a memory stream holding the payload");
    #endif
            AdrConverter.Serialize(args, ms);
            p = new AHPacket(1, 2, _node.Address, tun_ta.Target, AHPacket.AHOptions.Exact, 
                                 AHPacket.Protocol.Tunneling, ms.ToArray());
          }
#if TUNNEL_DEBUG
          Console.Error.WriteLine("Created a request packet.");
#endif
          EdgeCreationState ecs = new EdgeCreationState(localid, forwarding_edges, p, ecb);
          _ecs_ht[localid] = ecs;

#if TUNNEL_DEBUG
          Console.Error.WriteLine("Created an edge creation state for the tunnel edge: {0}", e);
#endif
        }
      }
      //we will defer this sending to next heartbeat; an artificial delay from out own side
      } catch(Exception e) {
	ecb(false, null, e);
      }
    }

    /**
     * This class keeps track of all tunnel edges that have been requested. 
     * Since creation of tunnel edges is not intantaneous, we record their creation state, 
     * and remove it once the edge is successfully created, or creation process times out. 
     */
    protected class EdgeCreationState {
      public static readonly TimeSpan ReqTimeout = new TimeSpan(0,0,0,0,5000);
      public readonly int Id;
      protected EdgeCreationCallback _ecb; 
      protected readonly Packet RequestPacket;
      protected readonly IList Senders;
      protected DateTime _last_send;
      protected object _last_send_lock;
      public const int MAX_ATTEMPTS = 4;
      protected int _attempts;
      public int Attempts { 
	get { 
	  return Thread.VolatileRead(ref _attempts);
	} 
      }
      protected readonly Random _r;
      protected Edge _edge; //reference type
      public Edge CreatedEdge { get { return _edge; } }
      public EdgeCreationState(int id, IList senders, Packet p, EdgeCreationCallback ecb) {
        Id = id;
        Senders = senders;
        _ecb = ecb;
        RequestPacket = p;
        _r = new Random();
        _attempts = MAX_ATTEMPTS;
        _last_send = DateTime.UtcNow;
        _last_send_lock = new object();
      }

      /**
       * This announces the Edge for this CreationState, and
       * sets the CreatedEdge variable.
       * @param success true if the creation succeeded.
       * @param e reference to the edge that got created (if success).
       * @param x exception that caused the edge creation to fail. 
       */
      public void CallECB(bool success, Edge e, Exception x) {
        //make sure the callback is only called once:
        EdgeCreationCallback ecb = Interlocked.Exchange(ref _ecb, null);
	if (ecb == null) {
          if(ProtocolLog.Exceptions.Enabled)
            ProtocolLog.Write(ProtocolLog.Exceptions, String.Format(
              "In TunnelEdgeListener CallECB called twice"));
        }
	//Set the edge:
	if( ecb != null ) {
	  _edge = e;
          ecb(success, e, x);
        }
      }

      /**
       * Resends our request to a randomly selected Sender in our
       * list of neighbors.
       */
      public void Resend() {
        DateTime now = DateTime.UtcNow;
        lock(_last_send_lock) {
          if (now - _last_send < EdgeCreationState.ReqTimeout) {
            return;
          }
          _last_send = now;
        }

	int new_val = Interlocked.Decrement(ref _attempts);
        if (new_val > 0) {
          /*
           * one of the senders might have closed
           * try three times to be sure
           */

          bool try_again = true;
          int count = 0;
          int edge_idx = _r.Next(0, Senders.Count);
          while( try_again ) {
            try {
              Edge e = (Edge) Senders[ edge_idx ];
              e.Send(RequestPacket);
              try_again = false;
            }
#if TUNNEL_DEBUG
            catch(Exception ex) {
              Console.Error.WriteLine(ex);
#else
            catch(Exception) {
#endif
              count++;
              //try the next edge:
              edge_idx = (edge_idx + 1) % Senders.Count;
              if( count >= 3 ) { try_again = false; }
            }
          }
        }
      }
    }
    protected Hashtable _ecs_ht;

    protected void TimeoutChecker(object o, EventArgs args) {
#if TUNNEL_DEBUG
      Console.Error.WriteLine("TimeoutChecker: Checking edge creation states at: {0}.", DateTime.Now);
#endif
      ArrayList to_remove = new ArrayList();
      ArrayList to_send = new ArrayList();
      lock (_sync) {
        foreach(DictionaryEntry de in _ecs_ht) {
          //check the status of corresponding edge
          int id = (int) de.Key;
          EdgeCreationState ecs = (EdgeCreationState) de.Value;
          if (ecs == null) {
#if TUNNEL_DEBUG
            Console.Error.WriteLine("This is wierd. How can ECS be null?");
#endif 
          }
          TunnelEdge e = (TunnelEdge) _id_ht[id];
          
          if (e == null) 
          {
#if TUNNEL_DEBUG
            Console.Error.WriteLine("TimeoutChecker: removing ECS (localid: {0}) for null edge. ", ecs.Id);
#endif
            to_remove.Add(ecs);
          }
          else if (e.RemoteID > 0) {
#if TUNNEL_DEBUG
            Console.Error.WriteLine("TimeoutChecker: removing ECS (complete edge localid: {0}) for: {1}", ecs.Id, e);
#endif
            to_remove.Add(ecs);
          }
          else if (ecs.Attempts <= 0) {
#if TUNNEL_DEBUG
            Console.Error.WriteLine("TimeoutChecker: removing ECS (timed out local id: {0}) for: {1}", ecs.Id, e);
#endif
            to_remove.Add(ecs);
          }
          else if (ecs.Attempts > 0) {
            to_send.Add(ecs);
          }
        }
        /* Hold the log for this part */
        foreach(EdgeCreationState ecs in to_remove) {
          _ecs_ht.Remove( ecs.Id );
          if( ecs.CreatedEdge == null ) {
            //We never announced a created edge, so remove this entry from the
            //id_ht:
            _id_ht.Remove( ecs.Id );
          }
        }
      }
      //the following should happen outside the lock
      foreach (EdgeCreationState ecs in to_remove) {
        ecs.CallECB(false, null, new EdgeException("Timed out on edge creation."));
      }
      foreach (EdgeCreationState ecs in to_send) {
#if TUNNEL_DEBUG
        Console.Error.WriteLine("Sending edge (localid: {0}) request", ecs.Id);
#endif
        ecs.Resend();
      }
    }

    /**
     * Start listening for edges.  Edges
     * received will be announced with the EdgeEvent
     * This must be called before CreateEdgeTo.
     */
    public override void Start() {
      if( 1 == Interlocked.Exchange(ref _isstarted, 1) ) {
        //We can't start twice... too bad, so sad:
        throw new Exception("Restart never allowed");
      }
#if TUNNEL_DEBUG
        Console.Error.WriteLine("Starting TunnelEdgeListener");
#endif
      Interlocked.Exchange(ref _running, 1);
      //Start listening to packets
      _node.GetTypeSource(PType.Protocol.Tunneling).Subscribe(this, null);
    }
    /**
     * Stop listening for edges.
     * The edgelistener may not be garbage collected
     * until this is called
     */
    public override void Stop() {
      Interlocked.Exchange(ref _running, 0);
      _node.HeartBeatEvent -= TimeoutChecker;
      _node.GetTypeSource(PType.Protocol.Tunneling).Unsubscribe(this);      
    }

    public TunnelEdgeListener(Node n) {
      _sync = new object();
#if TUNNEL_DEBUG
      Console.Error.WriteLine("Creating an instance of TunnelEdgeListsner");
#endif
      lock(_sync) {
        _node = n;
        
        //true for now, will change later
        _ta_auth = new ConstantAuthorizer(TAAuthorizer.Decision.Allow);
        

        _id_ht = new Hashtable(30, 0.15f);
        _remote_id_ht = new Hashtable();
        _rand = new Random();
        _ecs_ht = new Hashtable();
        

        _running = 0;
        _isstarted = 0;
        _node.HeartBeatEvent += new EventHandler(this.TimeoutChecker);
      }
    }
   
    /**
     * Each tunnel edge is represented using a pair of local and remote ids. 
     * Returns an edge, given its pairs of ids. 
     * @param localid local id for the edge
     * @param remoteid remote id for the edge
     * @returns reference to the edge, or null of th edge cannot be located. 
     */
    protected TunnelEdge GetTunnelEdge(int localid, int remoteid) {
      TunnelEdge edge_to_read = (TunnelEdge) _id_ht[localid];        
      if (edge_to_read != null) {
        if (edge_to_read.RemoteID == remoteid) {
          //It's all good
          return edge_to_read;
        }
        else {
          edge_to_read = null;
#if TUNNEL_DEBUG
            Console.Error.WriteLine("No edge to push packet into (Remote ID mismatch: old({0}) != new({1})), {2}",
                                    edge_to_read.RemoteID, remoteid, edge_to_read);
#endif
          }
      }
      else {
#if TUNNEL_DEBUG
          Console.Error.WriteLine("No edge to push packet into (unknown local id: {0}, null edge).", localid);
#endif
      }
      return edge_to_read;
    }
    
    /**
     * Handles packet received for the EdgeListener. It can be data received on 
     * a tunnel edge or packet for edge maintenance. 
     * @param packet that has been received.
     * @param return_path return path for the packet (to send it back).
     * @param state state supplied when subscribing to receive packets of some type. 
     */
    public void HandleData(MemBlock packet, ISender return_path, object state)
    {
      if (0 == _running) {
#if TUNNEL_DEBUG
        Console.Error.WriteLine("TunnelEdgeListener: not running (cannot handle packet)");
#endif 
        return;
      }
      //read the payload?
      MessageType type = (MessageType) packet[0];
      int remoteid = NumberSerializer.ReadInt(packet, 1);
      int localid = NumberSerializer.ReadInt(packet, 5);
      
#if TUNNEL_DEBUG
      Console.Error.WriteLine("TunnelEdgeListener: Receiving on base connection: {0}", return_path);
      Console.Error.WriteLine("Receiving edge packet, remoteid: {0}, localid: {1}", remoteid, localid);
#endif
      // 1 + 4 + 4 = 9
      MemBlock rest_of_payload = packet.Slice(9);
      if (type == MessageType.EdgeRequest) {
        HandleEdgeRequest(remoteid, localid, rest_of_payload, return_path);
      }
      else if (type == MessageType.EdgeResponse) {
        HandleEdgeResponse(remoteid, localid, rest_of_payload);
      }
      else if(type == MessageType.EdgeData) {
        HandleEdgeData(remoteid, localid, rest_of_payload);
      }
      else if (type == MessageType.EdgeControl) {
        HandleEdgeControl(remoteid, localid, rest_of_payload);
      }
      else if (type == MessageType.EdgeSync) {
        HandleEdgeSync(remoteid, localid, rest_of_payload);
      }
    }

    /**
     * Handle control messsages for edge maintenance. These messages relfect changes in 
     * connection tables at the edge endpoints. 
     * @param remoteid remote id for the edge. 
     * @param localid local id for the edge. 
     * @param rest_of_payload control message.
     */
    protected void HandleEdgeControl(int remoteid, int localid, MemBlock rest_of_payload) {
#if TUNNEL_DEBUG
        Console.Error.WriteLine("Receiving edge control");
#endif
      TunnelEdge tun_edge = null;
        lock( _sync ) {
          tun_edge = GetTunnelEdge(localid, remoteid);        
        }
        if (tun_edge != null) {
          ArrayList arg;
          ArrayList acquired = new ArrayList();
          ArrayList lost = new ArrayList();
          
          using(MemoryStream payload_ms = rest_of_payload.ToMemoryStream()) {
            arg = (ArrayList) AdrConverter.Deserialize(payload_ms);
            //list of acquired forwarders
            for (int i = 0; i < arg.Count; i++) {
              acquired.Add(AddressParser.Parse(MemBlock.Reference((byte[]) arg[i])));
            }
            arg = (ArrayList) AdrConverter.Deserialize(payload_ms);
            //list of lost forwarders
            for (int i = 0; i < arg.Count; i++) {
              lost.Add(AddressParser.Parse(MemBlock.Reference((byte[]) arg[i])));
            }
          }
          tun_edge.HandleControlPacket(acquired, lost);
        }
    }

    /**
     * Handle periodic synchronization messages for edge maintenance. 
     * @param remoteid remote id for the edge. 
     * @param localid local id for the edge. 
     * @param rest_of_payload control message.
     */
    protected void HandleEdgeSync(int remoteid, int localid, MemBlock rest_of_payload) {
#if TUNNEL_DEBUG
        Console.Error.WriteLine("Receiving edge control");
#endif
      TunnelEdge tun_edge = null;
        lock( _sync ) {
          tun_edge = GetTunnelEdge(localid, remoteid);        
        }
        if (tun_edge != null) {
          ArrayList arg;
          ArrayList forwarders = new ArrayList();
          using(MemoryStream payload_ms = rest_of_payload.ToMemoryStream()) {
            arg = (ArrayList) AdrConverter.Deserialize(payload_ms);
            //list of forwarders
            for (int i = 0; i < arg.Count; i++) {
              forwarders.Add(AddressParser.Parse(MemBlock.Reference((byte[]) arg[i])));
            }
          }
          tun_edge.HandleSyncPacket(forwarders);
        }
    }
    /**
     * Handle data received on an edge, look up the edge and announce the data. 
     * @param remoteid remote id for the edge. 
     * @param localid local id for the edge. 
     * @param rest_of_payload control message.
     */
    protected void HandleEdgeData(int remoteid, int localid, MemBlock rest_of_payload) {
#if TUNNEL_DEBUG
        Console.Error.WriteLine("Receiving edge data");
#endif
      TunnelEdge edge_to_read = GetTunnelEdge(localid, remoteid);        
      if (edge_to_read != null) {
        try {
          edge_to_read.ReceivedPacketEvent(rest_of_payload);
        }
        catch(EdgeException) {
          /* @todo
           * Potentially we might send a message back saying this edge
           * has been closed, just to make sure the other peer knows.
           */
        }
#if TUNNEL_DEBUG
        Console.Error.WriteLine("Receiving packet of length: {0} on edge: {1}",
                                      rest_of_payload.Length, edge_to_read);
#endif
      }
    }
    /**
     * When we get an a response to an EdgeRequest, we handle it here.
     * @param remoteid remote id for the edge. 
     * @param localid local id for the edge. 
     * @param rest_of_payload control message.
     */
    protected void HandleEdgeResponse(int remoteid, int localid, MemBlock rest_of_payload) {
        //assert (localid > 0) 
#if TUNNEL_DEBUG
        Console.Error.WriteLine("Receiving edge response");
#endif
        //possible response to our create edge request, make sure this 
        //is the case by verifying the remote TA
        ArrayList args = (ArrayList) AdrConverter.Deserialize(rest_of_payload);
        Address target = AddressParser.Parse(MemBlock.Reference((byte[]) args[0]));
        //list of packet forwarders
        ArrayList forwarders = new ArrayList();
        for (int i = 1; i < args.Count; i++) {
          forwarders.Add(AddressParser.Parse(MemBlock.Reference((byte[]) args[i])));
        }
        TunnelEdge e;
        EdgeCreationState ecs = null;
        lock( _sync ) {        
          //This gets the edge with the matching ids:
          e = GetTunnelEdge(localid, 0);
          if (e != null) {
  #if TUNNEL_DEBUG
            Console.Error.WriteLine("Must verify the remoteTA for the response");
  #endif
            TunnelTransportAddress remote_ta = new TunnelTransportAddress(target, forwarders);
  #if TUNNEL_DEBUG
            Console.Error.WriteLine("response.RemoteTA: {0}", remote_ta);
            Console.Error.WriteLine("edge.RemoteTA: {0}", e.RemoteTA);
  #endif
            TunnelTransportAddress e_rta = e.RemoteTA as TunnelTransportAddress;
            if (e_rta != null && e_rta.Target.Equals( remote_ta.Target ) ) {
              //Make sure they are trying to talk to us by checking
              //that the TA points to the same node
              e.RemoteID = remoteid;
  #if TUNNEL_DEBUG
              Console.Error.WriteLine("Edge protocol complete: {0}", e);
  #endif
              //raise an edge creation event 
              //this was an outgoing edge
              ecs = (EdgeCreationState) _ecs_ht[localid];
              _ecs_ht.Remove(localid);
              
            } else {
              //remote TAs do not match (ignore)
            } 
          }
        else {
          //We had no matching edge, or already handled this response
        }
          
        } //End of the lock

        if( ecs != null ) {
          try {
            e.CloseEvent += this.CloseHandler;
            //this would be an outgoing edge
#if TUNNEL_DEBUG
            Console.Error.WriteLine("remoteid: {0}, localid: {1}", remoteid, localid);
            Console.Error.WriteLine("announcing tunnel edge (outgoing): {0}", e);
#endif 
            ecs.CallECB(true, e, null);
          }
          catch(EdgeException) {
            /*
             * This edge has already closed so we need to handle it.
             * Note that we don't need to do CallECB which is handled
             * by the TimeoutChecker function.
             */
            CloseHandler(e, null);
          }
        }
        else {
            //This must have already been handled, we don't want to create
            //more than one edge, just ignore it.
        }
    }

    /**
     * When we get an EdgeRequest message, this is where we handle it.
     * @param remoteid remote id for the edge. 
     * @param localid local id for the edge. 
     * @param rest_of_payload control message.
     * @param return_path return path for the packet
     */
    protected void HandleEdgeRequest(int remoteid, int localid, MemBlock rest_of_payload, ISender return_path)
    {
#if TUNNEL_DEBUG
        Console.Error.WriteLine("Receiving edge request");
#endif
        //probably a new incoming edge
        bool is_new_edge = true;
        bool send_edge_event = false;
        TunnelEdge e = null;

        ArrayList args = (ArrayList) AdrConverter.Deserialize(rest_of_payload);
        Address target = AddressParser.Parse(MemBlock.Reference((byte[]) args[0]));
        //list of packet forwarders
        ArrayList forwarders = new ArrayList();
        for (int i = 1; i < args.Count; i++) {
          forwarders.Add(AddressParser.Parse(MemBlock.Reference((byte[]) args[i])));
        }
        //it is however possible that we have already created the edge locally

        lock( _sync ) {
        TunnelEdge e_dup = (TunnelEdge) _remote_id_ht[remoteid];
        if (e_dup != null) {
          TunnelTransportAddress remote_ta = new TunnelTransportAddress(target, forwarders);          
          //compare TAs
          TunnelTransportAddress e_rta = e_dup.RemoteTA as TunnelTransportAddress;
            if (e_rta != null && e_rta.Target.Equals( remote_ta.Target ) ) {
            //the fellow sent a duplicate edge request
            is_new_edge = false;
#if TUNNEL_DEBUG
            Console.Error.WriteLine("Duplicate edge request: from {0}", remote_ta);
#endif
            //but do send a response back
            //we also have to send a response back now
          } else {
            //someone else guessed the same id on its side
            //still okay, we can generate a unqiue id locally
          }
        } else {
          //this is the first edge request from a node and also
          //has a unique id on its side
          
        }
        if(is_new_edge) {
          do {
            localid = _rand.Next();
            //Make sure not to use negative ids
            if( localid < 0 ) { localid = ~localid; }
          } while( _id_ht.Contains(localid) || localid == 0 );
          
          //create an edge
          e = new TunnelEdge(this, true, _node, target, forwarders, localid, remoteid); 
#if TUNNEL_DEBUG
          Console.Error.WriteLine("Creating an instance of TunnelEdge: {0}", e);
          Console.Error.WriteLine("remoteid: {0}, localid: {1}", remoteid, localid);
#endif      

          _id_ht[localid] = e;
          _remote_id_ht[remoteid] = e;
          try {
            e.CloseEvent += this.CloseHandler;
          }
          catch {
            CloseHandler(e, null);
            throw;
          }
#if TUNNEL_DEBUG
          Console.Error.WriteLine("announcing tunnel edge (incoming): {0}", e);
#endif 
          send_edge_event = true;
        }
      }//Drop the lock

      /*
       * No matter what, we send a response back now
       */
        Packet p = null;
        using(MemoryStream ms = new MemoryStream()) {
          ms.WriteByte((byte) MessageType.EdgeResponse);
          NumberSerializer.WriteInt(localid, ms);
          NumberSerializer.WriteInt(remoteid, ms);
        
          //overwrite the first address in the edge response
          args[0] = _node.Address.ToMemBlock();

          AdrConverter.Serialize(args, ms);
          p = new AHPacket(1, 2, _node.Address, target, AHPacket.AHOptions.Exact, 
                                AHPacket.Protocol.Tunneling, ms.ToArray());
        }
        //send using the edge we received data on
#if TUNNEL_DEBUG
        Console.Error.WriteLine("Sending edge response: {0}", p);
#endif
        try {
          AHSender ahs = (AHSender)return_path;
          Edge from = (Edge)ahs.ReceivedFrom;
          from.Send(p);
#if TUNNEL_DEBUG
        } catch (Exception ex) {

          Console.Error.WriteLine(ex);
#else
        } catch (Exception) {
#endif
        }
        finally {
          if( send_edge_event ) {
            SendEdgeEvent(e);
          }
        }
    }

    /**
     * Handle sending of an edge control message, listing the connections acquired
     * and lost. 
     * @param e affected by the changes in connection table.
     * @param acquired list of connection (addresses) we acquired. 
     * @param lost list of connection (addresses) we lost. 
     */
    public void HandleControlSend(Edge e, IEnumerable acquired, IEnumerable lost) {
      if (0 == _running) {
        //do nothing
        return;
      }
      TunnelEdge tun_edge = (TunnelEdge)e;
      Packet p = null;
      using( MemoryStream ms = new MemoryStream() ) {
        ms.WriteByte((byte) MessageType.EdgeControl);
  
        NumberSerializer.WriteInt(tun_edge.ID, ms);
        NumberSerializer.WriteInt(tun_edge.RemoteID, ms);
        
        //write out newly acquired forwarders
        ArrayList arg1 = new ArrayList();
        if( acquired != null ) {
         foreach (Address addr in acquired) {
          //add forwarding addresses
          arg1.Add( addr.ToMemBlock() );
  #if TUNNEL_DEBUG
          Console.Error.WriteLine("Added a acquired address: {0}", addr);
  #endif 
         }
        }
  
        //write out lost addresses
        ArrayList arg2 = new ArrayList();
        if( lost != null ) {
         foreach (Address addr in lost) {
          //add forwarding addresses
          arg2.Add( addr.ToMemBlock() );
  #if TUNNEL_DEBUG
          Console.Error.WriteLine("Added a lost address: {0}", addr);
  #endif 
         }
        }
  
        AdrConverter.Serialize(arg1, ms);
        AdrConverter.Serialize(arg2, ms);
        
  
        p = new AHPacket(1, 2, _node.Address, tun_edge.Target,
                                AHPacket.AHOptions.Exact, 
                                AHPacket.Protocol.Tunneling, ms.ToArray());
      }
      

      ArrayList packet_senders = tun_edge.PacketSenders;
      int r_idx = _rand.Next(0, packet_senders.Count);
      int attempts = packet_senders.Count;
      while (attempts-- > 0) {
        ISender sender = null;
        try {
          int this_idx = (r_idx + attempts) % packet_senders.Count;
          sender = (ISender) packet_senders[this_idx];
#if TUNNEL_DEBUG
          Console.Error.WriteLine("Sending control out on base connection: {0}",
                                  _node.ConnectionTable.GetConnection((Edge) sender));
#endif
          sender.Send(p);
          return;
        } catch(EdgeClosedException) {
          //Just ignore it an move on to the next sender
        } catch(SendException) {
          //Just ignore it an move on to the next sender
        } catch(Exception ex) {
          if(ProtocolLog.UdpEdge.Enabled)
            ProtocolLog.Write(ProtocolLog.Exceptions, String.Format(
              "Error sending control using packet_sender: {0}, {1}", sender, ex));
        }
      }
    }

    /**
     * Handle sending of an edge synchronization. 
     * @param e tunnel edge.
     * @param forwarders list of forwarders for the tunnel edge. 
     */
    public void HandleSyncSend(Edge e, IEnumerable forwarders) {
      if (0 == _running) {
        //do nothing
        return;
      }
      TunnelEdge tun_edge = (TunnelEdge)e;
      Packet p = null;
      using( MemoryStream ms = new MemoryStream() ) {
        ms.WriteByte((byte) MessageType.EdgeSync);
  
        NumberSerializer.WriteInt(tun_edge.ID, ms);
        NumberSerializer.WriteInt(tun_edge.RemoteID, ms);
        

        ArrayList args = new ArrayList();
        foreach (Address addr in forwarders) {
          //add forwarding addresses
          args.Add( addr.ToMemBlock() );
        }
  
        AdrConverter.Serialize(args, ms);
  
        p = new AHPacket(1, 2, _node.Address, tun_edge.Target,
                                AHPacket.AHOptions.Exact, 
                                AHPacket.Protocol.Tunneling, ms.ToArray());
      }
      
     ArrayList packet_senders = tun_edge.PacketSenders;
     int r_idx = _rand.Next(0, packet_senders.Count);
     int attempts = packet_senders.Count;
     while (attempts-- > 0) {
       ISender sender = null;
       try {
         int this_idx = (r_idx + attempts) % packet_senders.Count;
         sender = (ISender) packet_senders[this_idx];
         
#if TUNNEL_DEBUG
         Console.Error.WriteLine("Sending edge sync on base connection: {0}",
                                  _node.ConnectionTable.GetConnection((Edge) sender));
#endif
         sender.Send(p);
         return;
       } catch(EdgeClosedException) {
         /*
          * Just ignore it an move on to the next sender
          */
       } catch(SendException x) {
         //Just ignore it an move on to the next sender
       } catch(Exception ex) {
         if(ProtocolLog.UdpEdge.Enabled)
           ProtocolLog.Write(ProtocolLog.Exceptions, String.Format(
             "Error sending edge sync on packet_sender: {0}, {1}", sender, ex));
       }
     }      
    }
     
    /*
     * When a edge closes we need to remove it from
     * our table, so we will know it is new if it comes
     * back.
     * @param edge edge that closed.
     * @param args arguments associated with the edge close event.
     */
    public void CloseHandler(object edge, EventArgs args)
    {
#if TUNNEL_DEBUG
      Console.Error.WriteLine("closing tunnel edge");
#endif
      TunnelEdge e = (TunnelEdge)edge;
      lock( _sync ) {
        _id_ht.Remove( e.ID );
        object re = _remote_id_ht[ e.RemoteID ];
        if( re == e ) {
          //_remote_id_ht only keeps track of incoming edges,
          //so, there could be two edges with the same remoteid
          //that are not equivalent.
          _remote_id_ht.Remove( e.RemoteID );
        }
      }
    }
  }
}
