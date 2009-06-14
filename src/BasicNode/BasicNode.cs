/*
Copyright (C) 2008  David Wolinsky <davidiw@ufl.edu>, University of Florida

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
using System.IO;
using System.Collections;
using System.Xml;
using System.Xml.Serialization;
using System.Threading;
using System.Net;

using Brunet;
using Brunet.Coordinate;
using Brunet.DistributedServices;
using Brunet.Rpc;
using Brunet.Security;

using System.Security.Cryptography;

/**
\namespace Brunet::Applications Provides BasicNode and core features
necessary for running Brunet.Node in a simple complete manner.
Besides providing basic functionality, this namespace and class offer 
some extra features, such as the ability to cleanly shutdown via ctrl-c,
a user configured Rpc method for providing information during a crawl
(see Information), and the ability to determine the IP addresses on the
local machines and their associated names.
\brief Provides BasicNode which implements a simple Brunet P2P Node.
*/
namespace Brunet.Applications {
  /// <summary>BasicNode provides the core Brunet features in a deployable model
  /// the inputs are a xml config file called NodeConfig, which specifies which
  /// if any services to deploy.  Other projects should inherit this as their
  /// base class rather than implementing their own interfaces to Brunet.</summary>
  public class BasicNode {
    /// <summary>The path to the NodeConfig.</summary>
    protected String _path;
    /// <summary>The NodeConfig that defines the Brunet.Node.</summary>
    protected NodeConfig _node_config;
    /// <summary>The Brunet.Node used to connect to the p2p network.</summary>
    protected StructuredNode _node;
    /// <summary>The p2p address for the local node.</summary>
    public Address LocalAddress { get { return _node.Address; } }
    /// <summary>An rpc interface over the local node.</summary>
    public RpcManager Rpc { get { return _node.Rpc; } }
    /// <summary>The Dht object used to participate in the dht.</summary>
    public IDht Dht { get { return _dht; } }
    protected IDht _dht;
    /// <summary>The NCService object used for this node.</summary>
    protected NCService _ncservice;
    /// <summary>The XmlRpc service provider.</summary>
    protected XmlRpcManagerServer _xrm;
    /// <summary>The shutdown service provider.</summary>
    public Shutdown Shutdown { get { return _shutdown; } }
    protected Shutdown _shutdown;
    /// <summary>Path to the node config (for updating it).</summary>
    protected string _node_config_path;
    /// <summary>True if the node should reincarnate itself if Node.Connect
    /// exits or throws an exception</summary>
    protected bool _running;
    /// <summary>Provides access to the BrunetSecurityOverlord</summary>
    public BrunetSecurityOverlord Bso { get { return _bso; } }
    protected BrunetSecurityOverlord _bso;

    /// <summary>Prepares a BasicNode.</summary>
    /// <param name="node_config">A node config object.</param>
    public BasicNode(NodeConfig node_config) {
      _node_config = node_config;
      _running = true;
      _shutdown = Shutdown.GetShutdown();
    }

    /// <summary>This should be called by the Main after all the setup is done
    /// this passes control to the _node and won't return until the program is
    /// exiting.  (It is synchronous.)</summary>
    public virtual void Run() {
      int sleep = 60, sleep_min = 60, sleep_max = 3600;
      DateTime start_time = DateTime.UtcNow;
      // Keep creating new nodes no matter what!
      while(_running) {
        CreateNode();
        new Information(_node, "BasicNode", _bso);
        Console.WriteLine("I am connected to {0} as {1}.  Current time is {2}.",
                                _node.Realm, _node.Address.ToString(), DateTime.UtcNow);
        _node.DisconnectOnOverload = true;
        start_time = DateTime.UtcNow;
        StartServices();
        _node.Connect();
        SuspendServices();
        if(!_running) {
          break;
        }
        // Assist in garbage collection
        DateTime now = DateTime.UtcNow;
        Console.WriteLine("Going to sleep for {0} seconds. Current time is: {1}", sleep, now);
        Thread.Sleep(sleep * 1000);
        if(now - start_time < TimeSpan.FromSeconds(sleep_max)) {
          sleep *= 2;
          sleep = (sleep > sleep_max) ? sleep_max : sleep;
        }
        else {
          sleep /= 2;
          sleep = (sleep < sleep_min) ? sleep_min : sleep;
        }
      }
    }

    /// <summary>Creates a Brunet.Node, the resulting node will be available in
    /// the class as _node.</summary>
    /// <remarks>The steps to creating a node are first constructing it with a
    /// namespace, optionally adding local ip addresses to bind to, specifying
    /// local end points, specifying remote end points, and finally registering
    /// the dht.</remarks>
    public virtual void CreateNode() {
      AHAddress address = null;
      try {
        address = (AHAddress) AddressParser.Parse(_node_config.NodeAddress);
      } catch {
        address = Utils.GenerateAHAddress();
      }

      _node = new StructuredNode(address, _node_config.BrunetNamespace);
      IEnumerable addresses = IPAddresses.GetIPAddresses(_node_config.DevicesToBind);

      if(_node_config.Security.Enabled) {
        if(_node_config.Security.SelfSignedCertificates) {
          SecurityPolicy.SetDefaultSecurityPolicy(SecurityPolicy.DefaultEncryptor,
              SecurityPolicy.DefaultAuthenticator, true);
        }

        byte[] blob = null;
        using(FileStream fs = File.Open(_node_config.Security.KeyPath, FileMode.Open)) {
          blob = new byte[fs.Length];
          fs.Read(blob, 0, blob.Length);
        }

        RSACryptoServiceProvider rsa_private = new RSACryptoServiceProvider();
        rsa_private.ImportCspBlob(blob);

        CertificateHandler ch = new CertificateHandler(_node_config.Security.CertificatePath);
        _bso = new BrunetSecurityOverlord(_node, rsa_private, _node.Rrm, ch);
        _bso.Subscribe(_node, null);

        _node.GetTypeSource(SecurityOverlord.Security).Subscribe(_bso, null);
        _node.HeartBeatEvent += _bso.Heartbeat;

        if(_node_config.Security.TestEnable) {
          blob = rsa_private.ExportCspBlob(false);
          RSACryptoServiceProvider rsa_pub = new RSACryptoServiceProvider();
          rsa_pub.ImportCspBlob(blob);
          CertificateMaker cm = new CertificateMaker("United States", "UFL", 
              "ACIS", "David Wolinsky", "davidiw@ufl.edu", rsa_pub,
              "brunet:node:abcdefghijklmnopqrs");
          Certificate cacert = cm.Sign(cm, rsa_private);

          cm = new CertificateMaker("United States", "UFL", 
              "ACIS", "David Wolinsky", "davidiw@ufl.edu", rsa_pub,
              address.ToString());
          Certificate cert = cm.Sign(cacert, rsa_private);
          ch.AddCACertificate(cacert.X509);
          ch.AddSignedCertificate(cert.X509);
        }
      }

      Brunet.EdgeListener el = null;
      foreach(NodeConfig.EdgeListener item in _node_config.EdgeListeners) {
        int port = item.port;
        if (item.type =="tcp") {
          try {
            el = new TcpEdgeListener(port, addresses);
          }
          catch {
            el = new TcpEdgeListener(0, addresses);
          }
        }
        else if (item.type == "udp") {
          try {
            el = new UdpEdgeListener(port, addresses);
          }
          catch {
            el = new UdpEdgeListener(0, addresses);
          }
        }
        else {
          throw new Exception("Unrecognized transport: " + item.type);
        }
        if(_node_config.Security.SecureEdgesEnabled) {
          el = new SecureEdgeListener(el, _bso);
        }
        _node.AddEdgeListener(el);
      }

      el = new TunnelEdgeListener(_node);
      if(_node_config.Security.SecureEdgesEnabled) {
        el = new SecureEdgeListener(el, _bso);
      }
      _node.AddEdgeListener(el);

      ArrayList RemoteTAs = null;
      if(_node_config.RemoteTAs != null) {
        RemoteTAs = new ArrayList();
        foreach(String ta in _node_config.RemoteTAs) {
          RemoteTAs.Add(TransportAddressFactory.CreateInstance(ta));
        }
        _node.RemoteTAs = RemoteTAs;
      }

      if (_node_config.NCService.Enabled) {
        _ncservice = new NCService(_node, _node_config.NCService.Checkpoint);

        if (_node_config.NCService.OptimizeShortcuts) {
          _node.Sco.TargetSelector = new VivaldiTargetSelector(_node, _ncservice);
        }
      }

      new TableServer(_node);
      _dht = new Dht(_node, 3, 20);
    }

    /// <summary>Starts services such as shutdown, rpcdht, and xmlrpc.  If you wish
    /// to have your own shutdown path, edit OnExit instead of this.  This can be
    /// called multiple times without negative effect.</summary>
    public virtual void StartServices() {
      _shutdown.OnExit += OnExit;

      if(_node_config.XmlRpcManager.Enabled && _xrm == null) {
        _xrm = new XmlRpcManagerServer(_node_config.XmlRpcManager.Port);
        _xrm.Update(_node, _bso);
        new RpcDht(_dht, _node);
      }
    }

    /**
    <summary>If you no longer want to serve due to inactivity or for whatever
    reason, this will be active until StartServices is called again.  This just
    stops serving the DhtRpc and XmlRpc services, but the ports remain open.
    </summary>
     */
    public virtual void SuspendServices() {
      if(_xrm != null) {
        _xrm.Suspend();
      }
    }

    /**
    <summary>This stops all services such as Xml and DhtRpc. Call this instead
    of SuspendServices if the node is shutting down or services are no longer 
    required and you would like to release the ports</summary>
    */
    public virtual void StopServices() {
      if(_xrm != null) {
        _xrm.Stop();
        _xrm = null;
      }
    }

    /**
    <summary>This method is registered as a delegate to Shutdown.OnExit and
    will be called when ctrl-c is pressed by the user.  This stops services,
    prevents the node from reincarnating, and then disconnects the node.
    </summary>
    */
    public virtual void OnExit() {
      if(_ncservice != null && _node_config.NCService.Checkpointing) {
        string checkpoint = _ncservice.GetCheckpoint();
        string prev_cp = _node_config.NCService.Checkpoint;
        string empty_cp = (new Point()).ToString();
        if(!checkpoint.Equals(prev_cp) && !checkpoint.Equals(empty_cp))
        {
          _node_config.NCService.Checkpoint = checkpoint;
          _node_config.WriteConfig();
        }
      }

      StopServices();
      _running = false;
      _node.Disconnect();
    }
  }
}
