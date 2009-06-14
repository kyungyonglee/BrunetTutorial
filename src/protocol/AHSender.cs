/*
This program is part of BruNet, a library for the creation of efficient overlay
networks.
Copyright (C) 2007 P. Oscar Boykin <boykin@pobox.com> University of Florida

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

using Brunet.Util;
using System.Threading;

namespace Brunet {

/**
 * This represents the fixed length header of AH Packets.
 * It covers the data after the AH PType and before the payload
 * PType.
 */
public class AHHeader : ICopyable {
  
  protected readonly ICopyable _data;

  public AHHeader(short hops, short ttl, Address source, Address dest, ushort options) {
    //Make the header part:
    byte[] header = new byte[ AHPacket.HeaderLength ];
    int offset = 0;
    //Write hops:
    NumberSerializer.WriteShort(hops, header, offset);
    offset += 2;
    NumberSerializer.WriteShort(ttl, header, offset);
    offset += 2;
    offset += source.CopyTo(header, offset);
    offset += dest.CopyTo(header, offset);
    NumberSerializer.WriteShort((short)options, header, offset);
    offset += 2;
    _data = MemBlock.Reference(header, 0, offset);
  }

  public int CopyTo(byte[] dest, int off) {
    return _data.CopyTo(dest, off);
  }

  public int Length { get { return _data.Length; } }
}

public class AHSender : ISender {
  static AHSender() {
    SenderFactory.Register("ah", CreateInstance);
    _buf_alloc = new BufferAllocator(System.UInt16.MaxValue);
  }

  protected static AHSender CreateInstance(Node n, string uri) {
    string s = uri.Substring(7);
    string []ss = s.Split(SenderFactory.SplitChars);
    string []dest = ss[1].Split(SenderFactory.Delims);
    Address target = AddressParser.Parse(dest[1]);
    string mode = (ss[2].Split(SenderFactory.Delims))[1];
    ushort option = SenderFactory.StringToUShort(mode);
    return new AHSender(n, target, option);
  }

  protected Node _n;
  protected readonly Address _dest;
  public Address Destination { get { return _dest; } }
  protected readonly Address _source;
  public Address Source { get { return _source; } }
  protected short _hops;
  public short Hops { get { return _hops; } }
  protected short _ttl;
  public short Ttl { get { return _ttl; } }
  protected ushort _options;
  public ushort Options { get { return _options; } }

  private static BufferAllocator _buf_alloc;

  protected ISender _from;
  /*
   * Every packet comes from somewhere, it is either locally generated,
   * or it came from an edge.  This ISender sends "back" from where the
   * packet came from
   *
   * If this a local packet, it was Received from the local node
   */
  public ISender ReceivedFrom { get { return _from; } }
  //This is the serialized header:
  protected MemBlock _header;
  protected int _header_length;

  public AHSender(Node n, Address destination, ushort options)
  : this( n, n, destination, n.DefaultTTLFor(destination), options) {

  }

  public AHSender(Node n, Address destination, short ttl, ushort options)
    : this(n, n, destination, ttl, options) {

  }
  public AHSender(Node n, ISender from, Address destination, short ttl, ushort options) {
    _n = n;
    _from = from;
    //Here are the fields in the order they appear:
    _hops = 0;
    _ttl = ttl;
    _source = n.Address;
    _dest = destination;
    _options = options;
  }
  /**
   * This is probably the most commonly used AHSender
   */
  public AHSender(Node n, Address destination)
    : this(n, destination, n.DefaultTTLFor(destination),
           AHPacket.AHOptions.AddClassDefault) {
    
  }

  override public bool Equals(object o) {
    AHSender ahs = o as AHSender;
    bool eq = false;
    if( ahs != null ) {
      eq = ahs.Destination.Equals( _dest );
      eq &= ( ahs._options == _options );
    }
    return eq;
  }

  override public int GetHashCode() {
    return _dest.GetHashCode();
  }

  public void Send(ICopyable data) {
    /*
     * Assemble an AHPacket:
     */
    if( _header == null ) {
      AHHeader ahh = new AHHeader(_hops, _ttl, _source, _dest, _options);
      _header = MemBlock.Copy(new CopyList( PType.Protocol.AH, ahh));
      _header_length = _header.Length;
    }
    byte[] ah_packet;
    int packet_length;
    int packet_offset;

    //Try to get the shared BufferAllocator, useful when
    //we don't know how big the data is, which in general
    //is just as expensive as doing a CopyTo...
    BufferAllocator ba = Interlocked.Exchange<BufferAllocator>(ref _buf_alloc, null);
    if( ba != null ) {
      try {
        ah_packet = ba.Buffer;
        packet_offset = ba.Offset;
        int tmp_off = packet_offset;
        tmp_off += _header.CopyTo(ah_packet, packet_offset);
        tmp_off += data.CopyTo(ah_packet, tmp_off);
        packet_length = tmp_off - packet_offset;
        ba.AdvanceBuffer(packet_length);
      }
      catch(System.Exception x) {
        throw new SendException(false, "could not write the packet, is it too big?", x);
      }
      finally {
        //Put the BA back
        Interlocked.Exchange<BufferAllocator>(ref _buf_alloc, ba);
      }
    }
    else {
      //Oh well, someone else is using the buffer, just go ahead
      //and allocate new memory:
      packet_offset = 0;
      packet_length = _header_length + data.Length;
      ah_packet = new byte[ packet_length ];
      int off_to_data = _header.CopyTo(ah_packet, 0);
      data.CopyTo(ah_packet, off_to_data);
    }
    MemBlock mb_packet = MemBlock.Reference(ah_packet, packet_offset, packet_length);
    /*
     * Now we announce this packet, the AHHandler will
     * handle routing it for us
     */
    _n.HandleData(mb_packet, _from, this);
  }

  public override string ToString() {
    return System.String.Format("AHSender(dest={0})",_dest);
  }

  /**
   * Converts the sender into a URI representation.
   * @returns URI for the sender.
   */
  public string ToUri() {
    return System.String.Format("sender:ah?dest={0}&mode={1}", _dest, SenderFactory.UShortToString(_options));
  }

}

/**
 * Send a message which should only be received by a node
 * which exactly matches the target address
 */
public class AHExactSender : AHSender {
  public AHExactSender(Node n, Address target)
    : base(n, target, n.DefaultTTLFor(target), AHPacket.AHOptions.Exact) { }
}

/**
 * Send a message which should only be received by a node
 * which is closest to the target address
 */
public class AHGreedySender : AHSender {
  public AHGreedySender(Node n, Address target)
    : base(n, target, n.DefaultTTLFor(target), AHPacket.AHOptions.Greedy) { }
}



/**
 * This handles AHPackets which arrive at the node
 */
public class AHHandler : IDataHandler {

  protected AHRouter _ah_router;
  protected DirectionalRouter _d_router;
  protected Node _n;

  /**
   * You still need to Subscribe this.  This constructor DOES NOT
   * do that
   */
  public AHHandler(Node n) {
    _n = n;
    _ah_router = new AHRouter((AHAddress)n.Address);
    _d_router = new DirectionalRouter((AHAddress)n.Address);
    _ah_router.ConnectionTable = _n.ConnectionTable;
    _d_router.ConnectionTable = _n.ConnectionTable;
  }
  /**
   * Here we handle routing AHPackets
   */
  public void HandleData(MemBlock data, ISender ret_path, object state) {
    /*
     * Unfortunately, the old code needs the full header intact, and
     * we have already eaten a byte of it, put it back:
     */
    MemBlock full_packet = data.ExtendHead(1);
    AHPacket p = new AHPacket(full_packet);
    //Route avoiding the edge we got the packet from:
    IRouter router = null;
    if( p.Destination.Class == 0 ) {
      router = _ah_router;
    }
    else {
      router = _d_router;
    }
    Edge edge_rec_from = ret_path as Edge;
    bool deliver_locally;
    router.Route(edge_rec_from, p, out deliver_locally);
    if( deliver_locally ) {
      //Send a response exactly back to the node that sent to us
      ISender resp_send = new AHSender(_n, ret_path, p.Source,
                                       _n.DefaultTTLFor(p.Source),
                                       AHPacket.AHOptions.Exact);
      //data:
      _n.HandleData( data.Slice(AHPacket.HeaderLength), resp_send, this); 
    }

  }

}

}
