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

using Brunet.DistributedServices;
using Brunet.Rpc;
using Brunet;

namespace Brunet.Applications {
  /// <summary>This class provides a layer on top of BasicNode to support
  /// creating multiple Brunet.Nodes in a single application.</summary>
  public class MultiNode: BasicNode {
    /// <summary>Contains a list of all the Brunet.Nodes.</summary>
    protected ArrayList _nodes;
    /// <summary>Contains a list of all the Brunet.Nodes Connect calls.</summary>
    protected ArrayList _threads;
    /// <summary>The total amount of Brunet.Nodes.</summary>
    protected int _count;
    protected NodeConfig _node_config_single;

    public MultiNode(NodeConfig node_config, int count) : base(node_config) 
    {
      _node_config_single = Utils.Copy<NodeConfig>(node_config);

      foreach(NodeConfig.EdgeListener item in _node_config.EdgeListeners) {
        item.port = 0;
      }

      _count = count;
      _nodes = new ArrayList(_count - 1);
      _threads = new ArrayList(_count - 1);
    }

    /// <summary>This is where the magic happens!  Sets up Shutdown, creates all
    /// the nodes, and call Connect on them in separate threads.</summary>
    public override void Run() {
      _shutdown = Shutdown.GetShutdown();
      _shutdown.OnExit += OnExit;

      for(int i = 1; i < _count; i++) {
        _node_config.NodeAddress = (Utils.GenerateAHAddress()).ToString();
        CreateNode();
        new Information(_node, "MultiNode", _bso);
        _nodes.Add(_node);
        Thread thread = new Thread(_node.Connect);
        thread.Start();
        _threads.Add(thread);
      }

      _node_config = _node_config_single;
      base.Run();
    }

    /// <summary>Disconnect all the nodes.  Called by Shutdown.OnExit</summary>
    public override void OnExit() {
      foreach(StructuredNode node in _nodes) {
        node.Disconnect();
      }
      base.OnExit();
    }
  }
}
