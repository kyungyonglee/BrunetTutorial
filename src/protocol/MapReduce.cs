/*
This program is part of BruNet, a library for the creation of efficient overlay
networks.
Copyright (C) 2008  Arijit Ganguly <aganguly@gmail.com>, University of Florida
                    P. Oscar Boykin <boykin@pobox.com>, University of Florida

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
using System.Collections;
using System.Collections.Specialized;

namespace Brunet {
  /** 
   * This class is the base class for a map-reduce task.
   * These tasks are completely stateless. All the state related 
   * to the progress of the computation is stored inside
   * a MapReduceComputation object.
   */
  public abstract class MapReduceTask {
    protected static readonly object _class_lock = new object();
    protected static int _log_enabled = -1;
    public static bool LogEnabled {
      get {
        lock(_class_lock) {
          if (_log_enabled == -1) {
            _log_enabled = ProtocolLog.MapReduce.Enabled ? 1: 0;
          }
          return (_log_enabled == 1);
        }
      }
    }

    protected void Log(string format_string, params object[] format_args) {
      if (LogEnabled) {
        string s = String.Format(format_string, format_args);
        ProtocolLog.Write(ProtocolLog.MapReduce, 
                          String.Format("{0}: {1}, {2}", _node.Address, this.GetType(), s));
      }
    }

    protected readonly object _sync;
    protected readonly Node _node;
    private string _task_name = string.Empty;
    /** unique type of the task. */
    public string TaskName {
      get {
        lock(_sync) {
          if (_task_name == string.Empty) {
            _task_name = this.GetType().ToString();
          }
          return _task_name;
        }
      }
    }

    /**
     * Constructor.
     * @param n local node
     */
    protected MapReduceTask(Node n) {
      _node = n;
      _sync = new object();
    }
    
    
    /** map function. */
    public abstract object Map(object map_arg);
    /** 
     * reduce function. 
     * @param reduce_arg arguments for the reduce
     * @param current_result accumulated result of reductions
     * @param child_rpc result from child computation
     * @param done out parameter (is the stopping criteria met)
     * @param child_results hashtable containing results from each child
     */
    public abstract object Reduce(object reduce_arg, object current_result, RpcResult child_rpc, out bool done);
    /** tree generator function. */
    public abstract MapReduceInfo[] GenerateTree(MapReduceArgs args);
  }
  
  /** 
   * This class provides an RPC interface into the map reduce functionality. 
   * To invoke a map-reduce task, we make an RPC call to 
   * "mapreduce.Start". The argument to this call is a
   * Hashtable describing the arguments to the call.
   * Later, it might be possible to add new methods that would allow 
   * inquiring state of a map-reduce task while it is running. 
   */  
  
  public class MapReduceHandler: IRpcHandler {
    protected readonly object _sync;
    protected readonly Node _node;
    protected readonly RpcManager _rpc;
    /** mapping of map-reduce task names to task objects. */
    protected readonly Hashtable _name_to_task;
    
    /**
     * Constructor
     * @param n local node
     */
    public MapReduceHandler(Node n) {
      _node = n;
      _rpc = RpcManager.GetInstance(n);
      _name_to_task = new Hashtable();
      _sync = new object();
    }
    
    /**
     * This dispatches the particular methods this class provides.
     * Currently, the only invokable method is:
     * "Start". 
     */
    public void HandleRpc(ISender caller, string method, IList args, object req_state) {
      if (method == "Start") {
        Hashtable ht = (Hashtable) args[0];
        MapReduceArgs mr_args = new MapReduceArgs(ht);
        string task_name = mr_args.TaskName;
        MapReduceTask task = null;
        lock(_sync) {
          task = (MapReduceTask) _name_to_task[task_name];
        }
        if (task != null) {
          Start(task, mr_args, req_state);
        } 
        else {
          throw new AdrException(-32608, "No mapreduce task with name: " + task_name);          
        }
      }
      else {
        throw new AdrException(-32601, "No Handler for method: " + method);
      }
    }
    
    /**
     * Allows subscribing new map-reduce tasks to the handler.
     * @param task an object representing the map-reduce task.
     */
    public void SubscribeTask(MapReduceTask task) {
      lock(_sync) {
        if (_name_to_task.ContainsKey(task.TaskName)) {
          throw new Exception(String.Format("Map reduce task name: {0} already registered.", task.TaskName));
        }
        _name_to_task[task.TaskName] = task;
      }
    }

    /**
     * Starts a map-reduce computation. 
     * @param task map reduce task to start.
     * @param args arguments for the map-reduce task. 
     * @param req_state RPC related state for the invocation.
     */
    protected void Start(MapReduceTask task, MapReduceArgs args, object req_state) {
      MapReduceComputation mr = new MapReduceComputation(_node, req_state, task, args);
      mr.Start();
    }
  }
    
  /** 
   * This class represents the arguments for a map-reduce computation.
   */
  public class MapReduceArgs {
    /** name of the task. */
    public readonly string TaskName;
    /** argument to the map function. */
    public readonly object MapArg;
    /** argument to the tree generating function. */
    public readonly object GenArg;
    /** argument to the reduce function. */
    public readonly object ReduceArg;

    /**
     * Constructor
     */
    public MapReduceArgs(string task_name, 
                         object map_arg,
                         object gen_arg,
                         object reduce_arg)
    {
      TaskName = task_name;
      MapArg = map_arg;
      GenArg = gen_arg;
      ReduceArg = reduce_arg;
    }
    
    /**
     * Constructor
     */
    public MapReduceArgs(Hashtable ht) {
      TaskName =  (string) ht["task_name"];
      MapArg =  ht["map_arg"];
      GenArg = ht["gen_arg"];
      ReduceArg = ht["reduce_arg"];
    }
    
    /**
     * Converts the arguments into a serializable hashtable
     */
    public Hashtable ToHashtable() {
      Hashtable ht = new Hashtable();
      ht["task_name"] = TaskName;
      ht["map_arg"] = MapArg;
      ht["gen_arg"] = GenArg;
      ht["reduce_arg"] = ReduceArg;
      return ht;
    }
  }

  /**
   * This class encapsulates information about a map-reduce invocation.
   */
  public class MapReduceInfo {
    /** next sender. */
    public readonly ISender Sender;
    /** map reduce arguments. */
    public readonly MapReduceArgs Args;
    public MapReduceInfo(ISender sender, MapReduceArgs args) {
      Sender = sender;
      Args = args;
    }
  }

  /**
   * This class represents an instance of a map-reduce computation. 
   */
  public class MapReduceComputation {
    protected static readonly object _class_lock = new object();
    protected static int _log_enabled = -1;
    public static bool LogEnabled {
      get {
        lock(_class_lock) {
          if (_log_enabled == -1) {
            _log_enabled = ProtocolLog.MapReduce.Enabled ? 1: 0;
          }
          return (_log_enabled == 1);
        }
      }
    }
    
    protected readonly Node _node;
    protected readonly RpcManager _rpc;
    protected readonly object _sync;
    
    // task executed in this computation instance
    protected readonly MapReduceTask _mr_task;

    // arguments to the task
    protected readonly MapReduceArgs _mr_args;

    // Rpc related state
    protected readonly object _mr_request_state;

    // result of the map function
    protected object _map_result;

    // accumulated result of reductions
    protected object _reduce_result;

    // indicating of the computation is over
    protected volatile bool _finished;
    
    //keep track of child computations.
    protected Hashtable _queue_to_child;

    
    /** 
     * Constructor
     * @param node local node
     * @param state RPC related state.
     * @param task map-reduce task.
     * @param args arguments to the map reduce task.
     */
    public MapReduceComputation(Node node, object state, 
                                MapReduceTask task,
                                MapReduceArgs args)
    {
      _node = node;
      _rpc = RpcManager.GetInstance(node);
      _mr_request_state = state;
      _mr_task = task;
      _mr_args = args;
      _queue_to_child = new Hashtable();
      _sync = new object();
      _finished = false;
    }
    
    /** Starts the computation. */
    public void Start() {
      //invoke map
      try {
        _map_result = _mr_task.Map(_mr_args.MapArg);
      } 
      catch(Exception x) {
        if (ProtocolLog.MapReduce.Enabled) {
          ProtocolLog.Write(ProtocolLog.MapReduce, 
                            String.Format("MapReduce: {0}, map exception: {1}.", _node.Address, x));        
        }
        _finished = true;
        SendResult(x);
        return;
      }

      if (LogEnabled) {
        ProtocolLog.Write(ProtocolLog.MapReduce,
                          String.Format("MapReduce: {0}, map result: {1}.", _node.Address, _map_result));
      }

      //do an initial reduction and see if we can terminate
      try {
        bool done; //out parameter
        _reduce_result = _mr_task.Reduce(_mr_args.ReduceArg, null, new RpcResult(null, _map_result), out done);

        if (LogEnabled) {
          ProtocolLog.Write(ProtocolLog.MapReduce,
                            String.Format("MapReduce: {0}, initial reduce result: {1}.", _node.Address, _reduce_result));
        }

        if (done) {
          _finished = true;
          SendResult(_reduce_result);
          return;
        }
      } catch(Exception x) {
        if (ProtocolLog.MapReduce.Enabled) {
          ProtocolLog.Write(ProtocolLog.MapReduce, 
                            String.Format("MapReduce: {0}, initial reduce exception: {1}.", _node.Address, x));
        }
        _finished = true;
        SendResult(x);
        return;
      }

      //compute the list of child targets
      MapReduceInfo[] child_mr_info = null;
      try {
        child_mr_info = _mr_task.GenerateTree(_mr_args);
      } catch (Exception x) {
        if (ProtocolLog.MapReduce.Enabled) {
          child_mr_info = new MapReduceInfo[0];
          ProtocolLog.Write(ProtocolLog.MapReduce,         
                            String.Format("MapReduce: {0}, generate tree exception: {1}.", _node.Address, x));
        }
      }
      
      if (LogEnabled) {
        ProtocolLog.Write(ProtocolLog.MapReduce,
                          String.Format("MapReduce: {0}, child senders count: {1}.", _node.Address, child_mr_info.Length));
      }

      if (child_mr_info.Length > 0) {
        foreach ( MapReduceInfo mr_info in child_mr_info) {
          Channel child_q = new Channel(1);
          //so far this is thread-safe
          _queue_to_child[child_q] = mr_info;
        }
        
        foreach (DictionaryEntry de in _queue_to_child) {
          Channel child_q = (Channel) de.Key;
          MapReduceInfo mr_info = (MapReduceInfo) de.Value;

          //the following will prevent the current object from going out of scope. 
          child_q.EnqueueEvent += new EventHandler(ChildCallback);
          try {
            _rpc.Invoke(mr_info.Sender, child_q,  "mapreduce.Start", mr_info.Args.ToHashtable());
          } catch(Exception) {
            ChildCallback(child_q, null);
          }
        }
      } else {
        // did not generate any child computations, return rightaway
        _finished = true;
        SendResult(_reduce_result);
        return;
      }
    }
    
    /**
     * Invoked when a child map-reduce computation finishes. 
     */
    protected void ChildCallback(object child_o, EventArgs child_event_args) {
      Channel child_q = (Channel) child_o;
      RpcResult child_result = null;
      if (child_q.Count > 0) {
        child_result = (RpcResult) child_q.Dequeue();
        if (LogEnabled) {
          ProtocolLog.Write(ProtocolLog.MapReduce,
                            String.Format("MapReduce: {0}, got child result: {1}.", _node.Address, child_result));
        }
      } 
      
      bool send_result = false;
      lock(_sync) {
        //only if computation has not finished
        if (!_finished) {
          bool stop = false;
          if (_queue_to_child.ContainsKey(child_q)) {
            _queue_to_child.Remove(child_q);
            if (child_result != null) {
              try {
                bool done; //out parameter
                _reduce_result = _mr_task.Reduce(_mr_args.ReduceArg, _reduce_result, child_result, out done);
                stop |= done;
              } catch(Exception x) {
                stop = true; //if an exception is thrown, we will stop.
                _reduce_result = x;
              }
            }
          }
          else {
            if (LogEnabled) {
              ProtocolLog.Write(ProtocolLog.MapReduce,
                                String.Format("MapReduce: {0}, child callback in an orphan queue.", _node.Address));
            }
          }
          
          _finished = (_queue_to_child.Keys.Count == 0) || stop;
          send_result = _finished;
        }
      }  //end of lock.
      
      if (send_result) {
        //only one thread will get here
        SendResult(_reduce_result);
        return;
      }
    }
    
    /**
     * Sends the result of the computation back.
     */ 
    protected void SendResult(object result) {
      if (LogEnabled) {
        ProtocolLog.Write(ProtocolLog.MapReduce,        
                          String.Format("MapReduce: {0}, sending back result: {1}.", _node.Address, result));
      }
      _rpc.SendResult(_mr_request_state, result);
    }
  }
}
  
