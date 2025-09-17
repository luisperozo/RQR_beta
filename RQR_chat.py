from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException, SSHDetect
import networkx as nx
import matplotlib.pyplot as plt
from typing import List, Dict, Final, Tuple, Optional, Union
import subprocess
import re
import matplotlib.pyplot as plt
import json
from ollama import ChatResponse, chat
from datetime import datetime
from config import SSH_USERNAME, SSH_PASSWORD, SSH_SECRET
import os
import difflib
import logging

NETMIKO_DEVICE_TYPES: Final[tuple[str, ...]] = (
    "cisco_ios",
    "cisco_xe",
    "cisco_xr",
    "arista_eos",
    "juniper_junos",
    "hp_procurve",
    "linux",
)

DEVICE_TAGS: Final[tuple[str, ...]] = (
    "Router",
    "Distribution Switch",
    "Access Switch",
    "Server",
    "Host",
    "Access Point",
    "Undetermined"
)

inventory_file_main = 'default_inventory.json'

topology_file_main = 'default_topology.json'

BASELINE_CONFIG_DIR: Final[str] = 'configs'

os.makedirs('logs', exist_ok=True)
log_filename = os.path.join('logs', f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
logging.basicConfig(filename=log_filename, level=logging.INFO, format='%(asctime)s - %(message)s')
  
def load_inventory(inventory_file: str) -> Optional[List[Dict[str, str]]]:
  """
  Loads network device inventory data from a JSON file. If not specified by user, then the function goes to a default inventory

  Args:
      inventory_file (str): Path to the inventory file. Defaults to 'default_inventory.json'.

  Returns:
      Optional[List[Dict[str, str]]]: A list of inventory entries if successful, otherwise None.
  """
  if inventory_file == '':
    inventory_file = inventory_file_main
  try:
      with open(inventory_file, 'r') as f:
          return json.load(f)
  except Exception:
      return None

def save_inventory(
  object: List[Dict[str, Union[str, Dict[str, str]]]],
  inventory_file: str = 'default_inventory.json'
) -> bool:
  """
  Saves the inventory list to a JSON file.

  Args:
      object (List[Dict[str, Union[str, Dict[str, str]]]]): The inventory list to save.
      inventory_file (str): Path to the JSON file where the inventory will be saved.
                            Defaults to 'default_inventory.json'.

  Returns:
      bool: True if saving succeeded, False otherwise.
  """
  try:
      with open(inventory_file, "w") as f:
          json.dump(object, f, indent=4)
      return True
  except:
      return False

def load_topology(topology_file: str) -> Optional[List[Dict[str, str]]]:
  """
  Loads network topology data from a JSON file.

  Args:
      topology_file (str): Path to the topology JSON file.

  Returns:
      Optional[List[Dict[str, str]]]: A list representing the network topology, or None if loading fails.
  """
  if topology_file == '':
    topology_file = topology_file_main
  try:
      with open(topology_file, 'r') as f:
          return json.load(f)
  except Exception:
      return None

def save_topology(
  object: List[Dict[str, Union[str, Dict[str, str]]]],
  topology_file: str = 'default_topology.json'
) -> bool:
  """
  Saves network topology data to a JSON file.

  Args:
      object (List[Dict[str, Union[str, Dict[str, str]]]]): The topology structure to save.
      topology_file (str): Path to the topology JSON file. Defaults to 'default_topology.json'.

  Returns:
      bool: True if the file was saved successfully, False otherwise.
  """
  try:
      with open(topology_file, "w") as f:
          json.dump(object, f, indent=4)
      return True
  except:
      return False

def test_reachability(
  ip: Optional[str] = '',
  hostname: Optional[str] = ''
) -> Dict[str,str]:
  """
  Checks the reachability of a device using either ping or SSH as tools. 

  Args:
      ip (Optional[str]): The IP address of the device to check.
      hostname (Optional[str]): The hostname of the device to check.

  Returns:
      Dict[str,str]: A dict with the result being the key, and the value, a str that gives a description of the result.
  """
  inventory_list = load_inventory(inventory_file_main)
  if ip != '' and inventory_list is None:
      result = subprocess.run(
          ["ping", '-c', '5', ip],
          stdout=subprocess.DEVNULL,
          stderr=subprocess.DEVNULL,
      )
      return {'result':'The IP address '+ip+' is reachable but there is no inventory'}  if result.returncode == 0 else {'result': 'The IP address '+ip+' is not reachable'}
  if hostname != '' and inventory_list is None:
      return {'result': 'It was not possible to determine the IP address of the host. When providing a hostname, the inventory file must be provided'} 
  for device in inventory_list:
      if ip == device['ip'] or hostname == device['hostname']:
          ip = device['ip']
          hostname = device['hostname']
          try:
              device = {
              'device_type': device['device_type'],
              'ip': device['ip'],
              'username': SSH_USERNAME,
              'password': SSH_PASSWORD,
              'secret': SSH_SECRET
              }
              conn = ConnectHandler(**device)
              conn.disconnect()
              return {'result':'The ' + hostname +', IP '+ip+', is reachable and accessible with SSH'}
          except (NetmikoTimeoutException):
              result = subprocess.run(
                  ["ping", '-c', '5', ip],
                  stdout=subprocess.DEVNULL,
                  stderr=subprocess.DEVNULL,
              )
              return {'result':'The ' + hostname +', IP '+ip+', is reachable but does not support SSH'} if result.returncode == 0 else {'result': 'The ' + hostname + ', IP '+ip+', is not reachable'}
          except (NetmikoAuthenticationException):
              return {'result': 'The ' + hostname +', IP '+ip+', is reachable and supports SSH, but authentication credentials failed'}
          except Exception as e:
              return {'result':'Unexpected error with' + hostname +': ' + e}
  if ip:
      result = subprocess.run(
          ["ping", '-c', '5', ip],
          stdout=subprocess.DEVNULL,
          stderr=subprocess.DEVNULL,
      )
      return {'result':'The ' + hostname+', IP '+ip+', is reachable but it is not saved in the inventory'} if result.returncode == 0 else {'result': 'The ' + hostname +', IP '+ip+', is not reachable'}
  elif hostname:
      return {'result':"The shared hostname " + hostname + " doesn't belong to any device on the inventory"}
  else: 
      return {'result':"Either the ip or the hostname arguments are required to be parse to the function"}

def topology_creation(
  topology_file: str = 'default_topology.json'
) -> Union[Dict[str, List[str]], str] :
  """
  Connects to each Cisco IOS device in the inventory, retrieves CDP neighbors,
  and builds a topology map. Saves the result to a JSON file.

  Args:
      topology_file (str): Path where the topology JSON will be saved. Defaults to 'default_topology.json'.

  Returns:
      Dict[str, List[str]]: A dictionary with three keys:
          - 'devices and CDP neighbors': list of discovered neighbors per device,
          - 'devices not able to authenticate': list of devices with failed SSH login, but reachable
          - 'devices not reachable' : list of devices that are not reachable.
  """
  inventory_list = load_inventory(inventory_file_main)
  if inventory_list is None:
      return 
  neighbors_list = []
  devices_not_reachable = []
  devices_credentials_error = []
  for device in inventory_list:
      if device['device_type']=='cisco_ios':
          device_netmiko_format = {
                  'device_type': device['device_type'],
                  'ip': device['ip'],
                  'username': SSH_USERNAME,
                  'password': SSH_PASSWORD,
                  'secret': SSH_SECRET
                  }
          try:
              net_connect = ConnectHandler(**device_netmiko_format)
              net_connect.enable()
              index = next((i for i, d in enumerate(neighbors_list) if device['hostname'] in d),False)
              if not index:
                  neighbors_list.append({device['hostname']:[]})
                  index=-1
              output = net_connect.send_command('show cdp neighbors')
              cdp_pattern = re.compile(
                  r'^(?P<device>\S+)\s+'
                  r'(?P<interface>(?:Gig|Fas|Ten) (?:\d+/\d+|\d+/\d+/\d+)).*?'
                  r'(?P<remote_interface>(?:Gig|Fas|Ten) (?:\d+/\d+|\d+/\d+/\d+))', 
                  re.MULTILINE
              )
              matches = cdp_pattern.findall(output)
              if matches:
                  for cdp_neighbor, local_interface, remote_interface  in matches:
                      neighbors_list[index][device['hostname']].append({
                          'local_interface': local_interface,
                          'neighbor': cdp_neighbor.split('.')[0], 
                          'remote_interface': remote_interface
                      })
              else:
                  neighbors_list.append({device['hostname']:"no neighbors"})
              net_connect.disconnect()
          except NetmikoTimeoutException:
              devices_not_reachable.append(device['hostname'])
          except NetmikoAuthenticationException:
              devices_credentials_error.append(device['hostname'])
  save_topology(topology_file=topology_file, object=neighbors_list)
  topology_ilustration(neighbors_list)
  return {
      'devices and CDP neighbors': neighbors_list, 
      'devices not reachable': devices_not_reachable, 
      'devices not able to authenticate': devices_credentials_error
  }

def topology_ilustration(topology_list: List[Dict[str, List[Dict[str, str] | str]]] | None, output_file: str = "topology_diagram.png") -> str:
  """
  Generates and saves a styled network topology diagram as a PNG image.

  Args:
      topology_list: The list of device-to-neighbors mappings.
      output_file: File path to save the diagram PNG. Default is 'topology_diagram.png'.

  Returns:
      str: Success message or error description.
  """
  if topology_list is None:
      return 'The topology file is not returning its contents correctly'

  G = nx.MultiGraph()
  added_links = set()
  list_hostnames = []
  for device_dic in topology_list:
      list_hostnames.append(list(device_dic.keys())[0])
  for local_device_dict in topology_list:
      for local_device_name, neighbors_list in local_device_dict.items():
          for neighbor_info in neighbors_list:
              remote_device_name = neighbor_info['neighbor']
              local_interface =  neighbor_info['local_interface']
              remote_interface = neighbor_info['remote_interface']
              link_key = frozenset([
                  local_device_name, remote_device_name,
                  local_interface,
                  remote_interface
                  ])
              if link_key not in added_links and neighbor_info['neighbor'] in list_hostnames:
                  G.add_edge(
                      local_device_name,
                      remote_device_name,
                      local_int = local_interface,
                      remote_int = remote_interface 
                  )
              added_links.add(link_key)

  pos = nx.spring_layout(G, seed=42)
  plt.figure(figsize=(12, 8))

  nx.draw_networkx_nodes(G, pos, node_size=1500, node_color='lightblue')
  nx.draw_networkx_labels(G, pos, font_weight='bold')

  edge_counts = {}
  for u, v, k in G.edges(keys=True):
      key = tuple(sorted([u, v]))
      edge_counts[key] = edge_counts.get(key, 0) + 1

  edge_offsets = {
      1: [0],
      2: [-0.2, 0.2],
      3: [-0.3, 0, 0.3],
      4: [-0.4, -0.15, 0.15, 0.4],
  }

  edge_index_tracker = {}

  for u, v, key, data in G.edges(keys=True, data=True):
      pair = tuple(sorted([u, v]))
      count = edge_counts[pair]
      offset_list = edge_offsets.get(count, [-0.3, -0.1, 0.1, 0.3])  # fallback
      if pair not in edge_index_tracker:
          edge_index_tracker[pair] = 0
      idx = edge_index_tracker[pair]
      rad = offset_list[idx % len(offset_list)]
      edge_index_tracker[pair] += 1

      nx.draw_networkx_edges(
          G,
          pos,
          edgelist=[(u, v)],
          connectionstyle=f'arc3,rad={rad}',
          width=2,
          alpha=0.8,
          edge_color='gray'
      )

      x1, y1 = pos[u]
      x2, y2 = pos[v]
      dx, dy = x2 - x1, y2 - y1
      length = (dx ** 2 + dy ** 2) ** 0.5 or 1  

      norm_dx, norm_dy = dx / length, dy / length

      perp_dx, perp_dy = -norm_dy, norm_dx

      along = 0.15  
      outward = rad * 0.25  

      local_pos = (
          x1 + along * dx + outward * perp_dx,
          y1 + along * dy + outward * perp_dy
      )
      remote_pos = (
          x2 - along * dx + outward * perp_dx,
          y2 - along * dy + outward * perp_dy
      )

      plt.text(*local_pos, data['local_int'], fontsize=9, color='green',
              ha='center', va='center', bbox=dict(boxstyle='round,pad=0.2', fc='white', ec='green', alpha=0.5))
      plt.text(*remote_pos, data['remote_int'], fontsize=9, color='darkred',
              ha='center', va='center', bbox=dict(boxstyle='round,pad=0.2', fc='white', ec='darkred', alpha=0.5))

  plt.title("Network Topology based on Cisco Discovery Protocol", fontsize=16)
  plt.axis("off")
  plt.tight_layout()
  plt.savefig(output_file, format="png", dpi=300)
  plt.close()

  return f"Topology diagram saved to {output_file}"

def add_device_inventory(
  hostname: str,
  ip: str,
  device_type: Optional[str] = None,
  tag: str = DEVICE_TAGS[-1],
  description: str = 'No description'
) -> Tuple[List[Dict[str, str]], str]:
  """
  Adds a device to the inventory list. If device_type is unknown, attempts SSH autodetection.
  
  Args:
      hostname (str): Hostname of the device to add.
      ip (str): IP address of the device.
      device_type (Optional[str]): Netmiko device_type string. If not provided, autodetection is attempted.
      tag (str): Optional classification tag. Defaults to the last entry in DEVICE_TAGS.
      description (str): Optional description of the device.

  Returns:
      Tuple[List[Dict[str, str]], str]: Updated inventory and a status message.
  """
  inventory_list = load_inventory(inventory_file_main)
  for device_in_inventory in inventory_list:
      if hostname == device_in_inventory['hostname'] :
          return inventory_list, 'The device ' + hostname + ' is already saved in the inventory with IP address ' + device_in_inventory['ip']
      elif ip == device_in_inventory['ip']:
          return inventory_list, 'The IP address ' + ip + ' is already saved in the inventory with hostname ' + device_in_inventory['hostname']
  if tag not in DEVICE_TAGS:
      tag = DEVICE_TAGS[-1]
  if device_type not in NETMIKO_DEVICE_TYPES:
      try:
          guesser = SSHDetect(
              device_type="autodetect",
              ip=ip,
              secret=SSH_SECRET,
              password=SSH_PASSWORD,
              username=SSH_USERNAME,
          )
          device_type = guesser.autodetect()
          inventory_list.append({
              'hostname': hostname,
              'ip': ip,
              'device_type': device_type,
              'tag': tag,
              'description': description
          })
          save_inventory(inventory_list)
          return {'inventory': inventory_list,
              'result': 'Device reachable'
        }
      except NetmikoTimeoutException:
          inventory_list.append({
              'hostname': hostname,
              'ip': ip,
              'device_type': device_type,
              'tag': tag,
              'description': description
          })
          save_inventory(inventory_list)
          return {'inventory': inventory_list,
              'result': 'device is not reachable or does not support SSH, but it was added to the inventory'
        }
      except NetmikoAuthenticationException:
          inventory_list.append({
              'hostname': hostname,
              'ip': ip,
              'device_type': device_type,
              'tag': tag,
              'description': description
          })
          save_inventory(inventory_list)
          return {'inventory': inventory_list,
              'result': 'credentials are not working for the device, but it was added to the inventory'
        }
      except Exception as e:
          return {'inventory': inventory_list,
              'result': 'The following error appeared: ' + e
        }
  else:
      explanation = test_reachability(ip=ip)
      inventory_list.append({
          'hostname': hostname,
          'ip': ip,
          'device_type': device_type,
          'tag': tag,
          'description': description
      })
      save_inventory(inventory_list)
      return {'inventory': inventory_list,
              'result': explanation['result']
        }

def delete_device_inventory(
  ip: Optional[str] = None,
  hostname: Optional[str] = None
) -> Dict[str,str]:
  """
  Removes a device from the inventory based on IP or hostname.

  Args:
      inventory_list (List[Dict[str, str]]): The current inventory list.
      ip (Optional[str]): The IP address of the device to remove.
      hostname (Optional[str]): The hostname of the device to remove.

  Returns:
      Tuple[List[Dict[str, str]], Union[Dict[str, str], str]]: Updated inventory and either the deleted device or a message.
  """
  inventory_list = load_inventory(inventory_file_main)
  if ip is None and hostname is None:
      return {'result': 'No modification to the inventory, you must provide at least an IP address or a hostname'}
  
  for i, device in enumerate(inventory_list):
      if ip == device['ip'] or hostname == device['hostname']:
          deleted_device = inventory_list.pop(i)
          save_inventory(inventory_list)
          return {'inventory': inventory_list,
                  'deleted_device': deleted_device
                  } 
  
  return {'inventory': inventory_list,
        'result': 'The IP address or the hostname provided were not found in the inventory list'
        } 

def get_device_logs(ip: Optional[str] = '', hostname: Optional[str] = '') -> Dict[str, str]:
    """
    Connects via SSH to a Cisco device (by IP or hostname) and retrieves system logs.

    Args:
        ip (Optional[str]): IP address of the device.
        hostname (Optional[str]): Hostname of the device.
    Returns:
        Dict[str, str]: Dictionary with logs under the 'logs' key, or error message under 'error'.
    """
    inventory_list = load_inventory(inventory_file_main)
    if (ip == '' and hostname == '') or (not ip and not hostname):
        return {'error': 'You must provide either an IP address or a hostname.'}
    for device in inventory_list:
        if hostname == device['hostname'] or ip == device['ip']:
            hostname = device['hostname']
            ip = device['ip']
            device = {
                    'device_type': device['device_type'],
                    'ip': ip,
                    'username': SSH_USERNAME,
                    'password': SSH_PASSWORD,
                    'secret': SSH_SECRET,
                }
            try:
                net_connect = ConnectHandler(**device)
                net_connect.enable()
                logs_output = net_connect.send_command("show logging")
                net_connect.disconnect()
                return {'logs': logs_output}
            except NetmikoTimeoutException:
                return {'result': 'The ' + hostname +', IP '+ip+', is not reachable or port 22 is closed'}
            except NetmikoAuthenticationException:
                return {'result': 'The ' + hostname +', IP '+ip+', is reachable and supports SSH, but authentication credentials failed'}
            except Exception as e:
                return {'error': 'An unexpected error occurred: ' + e}
        else:
            {'result': 'The provided details were not found in the inventory'}

def configure_access_interface(ip: Optional[str] = '', hostname: Optional[str] = '', interface: str = '', vlan: str = '1') -> Dict[str, str]:
    """
    Configure the provided interface as an access interface for the VLAN specified and the switch Specified

    Args:
        ip (Optional[str]): IP address of the device.
        hostname (Optional[str]): Hostname of the device.
        interface (str): Interface name (e.g., 'GigabitEthernet0/1') to configure.
        vlan (str): VLAN number to assign the access port to. Defaults to '1'.

    Returns:
        Dict[str, str]: Result of the configuration attempt or an error message.
    """
    if (ip == '' and hostname == '') or interface == '':
        return {'error': 'You must provide an IP or hostname and a valid interface name.'}

    inventory_list = load_inventory(inventory_file_main)

    for device in inventory_list:
        if hostname == device['hostname'] or ip == device['ip']:
            hostname = device['hostname']
            ip = device['ip']
            device = {
                'device_type': device['device_type'],
                'ip': ip,
                'username': SSH_USERNAME,
                'password': SSH_PASSWORD,
                'secret': SSH_SECRET,
            }
            try:
                net_connect = ConnectHandler(**device)
                net_connect.enable()

                output = net_connect.send_command(f"show interface {interface} switchport")
                if "Administrative Mode: trunk" in output:
                    net_connect.disconnect()
                    return {'result': f"Interface {interface} is statically configured as trunk. No changes made. You are trying to break the network"}

                config_commands = [
                    "interface " + interface,
                    "switchport mode access",
                    "switchport access vlan " + vlan,
                    "switchport nonegotiate",
                    "no shutdown"
                ]
                net_connect.send_config_set(config_commands)
                net_connect.disconnect()
                return {'result': "Interface " + interface + " has been successfully configured as an access"}

            except NetmikoTimeoutException:
                return {'result': 'The ' + hostname +', IP '+ip+', is not reachable or port 22 is closed'}
            except NetmikoAuthenticationException:
                return {'result': 'The ' + hostname +', IP '+ip+', is reachable and supports SSH, but authentication credentials failed'}
            except Exception as e:
                return {'error': "An unexpected error occurred: " + e}

    return {'result': 'The provided device details were not found in the inventory.'}

def verify_config(
  ip: Optional[str] = '',
  hostname: Optional[str] = ''
) -> Dict[str, Union[List[str], str]]:
  """
  Compares the running configuration of a single device against its baseline configuration.

  Args:
      ip (Optional[str]): IP address of the device to verify.
      hostname (Optional[str]): Hostname of the device to verify.

  Returns:
      Dict[str, Union[List[str], str]]: A dictionary that contains one of the following keys:
          - ``differences`` with the unified diff between the baseline and running configuration
            when the device is reachable.
          - ``unreachable`` when the device cannot be contacted or authenticated.
          - ``error`` when the verification cannot be completed due to missing inventory data,
            missing baseline files, or unexpected exceptions.
          The dictionary also includes the ``device`` key whenever a device from the inventory is
          successfully identified.
  """

  if (ip == '' or ip is None) and (hostname == '' or hostname is None):
      return {'error': 'You must provide either an IP address or a hostname.'}

  inventory_list = load_inventory(inventory_file_main)
  if not inventory_list:
      return {'error': 'Inventory is empty or could not be loaded.'}

  selected_device: Optional[Dict[str, str]] = None
  for device in inventory_list:
      device_hostname = device.get('hostname', '')
      device_ip = device.get('ip', '')
      if (hostname and hostname == device_hostname) or (ip and ip == device_ip):
          selected_device = device
          break

  if selected_device is None:
      identifier = hostname or ip or 'unknown device'
      return {'error': f'Device {identifier} was not found in the inventory.'}

  resolved_hostname = selected_device.get('hostname', '').strip() if isinstance(selected_device.get('hostname'), str) else ''
  resolved_ip = selected_device.get('ip', '').strip() if isinstance(selected_device.get('ip'), str) else ''
  device_label = resolved_hostname or resolved_ip or 'unknown device'

  if not resolved_hostname:
      return {'error': 'Device hostname is missing in the inventory; unable to determine baseline file.'}

  baseline_filename = f"{resolved_hostname}_baseline.txt"
  baseline_path = os.path.join(BASELINE_CONFIG_DIR, baseline_filename)

  if not os.path.isfile(baseline_path):
      return {'device': device_label, 'error': f'Baseline file not found: {baseline_path}'}

  device_conn = {
      'device_type': selected_device.get('device_type', ''),
      'ip': resolved_ip,
      'username': SSH_USERNAME,
      'password': SSH_PASSWORD,
      'secret': SSH_SECRET,
  }

  try:
      net_connect = ConnectHandler(**device_conn)
      net_connect.enable()
      running_config = net_connect.send_command('show running-config')
      net_connect.disconnect()
  except NetmikoTimeoutException:
      return {'device': device_label, 'unreachable': f'{device_label} - not reachable or port 22 is closed'}
  except NetmikoAuthenticationException:
      return {'device': device_label, 'unreachable': f'{device_label} - reachable but authentication credentials failed'}
  except Exception as exc:
      return {'device': device_label, 'error': f'An unexpected error occurred: {exc}'}

  try:
      with open(baseline_path, 'r') as baseline_file:
          baseline = baseline_file.read()
  except Exception:
      return {'device': device_label, 'error': f'Baseline file could not be read: {baseline_path}'}

  diff = list(
      difflib.unified_diff(
          baseline.splitlines(),
          running_config.splitlines(),
          fromfile='baseline',
          tofile='running-config',
          lineterm=''
      )
  )

  return {'device': device_label, 'differences': diff}


def backup_device_configs(backup_dir: str = 'backups') -> Dict[str, Union[Dict[str, str], List[str]]]:
  """
  Creates running-configuration backups for every reachable device in the inventory.

  Args:
      backup_dir (str): Directory where backups will be stored. Defaults to ``backups``.

  Returns:
      Dict[str, Union[Dict[str, str], List[str]]]:
          - ``successful_backups`` maps hostnames to the backup file that was written.
          - ``devices_not_reachable`` lists devices that could not be contacted.
          - ``devices_with_authentication_error`` lists devices with credential failures (optional).
          - ``errors`` maps hostnames to the error message encountered while saving the backup (optional).
  """
  inventory_list = load_inventory(inventory_file_main)

  if not inventory_list:
      return {
          'successful_backups': {},
          'devices_not_reachable': [],
          'errors': {'inventory': 'Inventory is empty or could not be loaded.'}
      }

  os.makedirs(backup_dir, exist_ok=True)
  timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

  successful_backups: Dict[str, str] = {}
  devices_not_reachable: List[str] = []
  devices_auth_failed: List[str] = []
  errors: Dict[str, str] = {}

  for device in inventory_list:
      hostname = device.get('hostname', 'unknown')
      ip_address = device.get('ip', '')
      device_label = hostname if hostname not in ('', 'unknown') else ip_address or 'unknown_device'

      device_conn = {
          'device_type': device.get('device_type', ''),
          'ip': ip_address,
          'username': SSH_USERNAME,
          'password': SSH_PASSWORD,
          'secret': SSH_SECRET,
      }

      try:
          net_connect = ConnectHandler(**device_conn)
          try:
              net_connect.enable()
          except Exception:
              # Some platforms may not require/allow enable mode; continue if it fails.
              pass
          running_config = net_connect.send_command('show running-config')
          net_connect.disconnect()
      except NetmikoTimeoutException:
          devices_not_reachable.append(f"{device_label} ({ip_address})" if ip_address else device_label)
          continue
      except NetmikoAuthenticationException:
          devices_auth_failed.append(f"{device_label} ({ip_address})" if ip_address else device_label)
          continue
      except Exception as exc:
          errors[device_label] = f"Unexpected error while collecting configuration: {exc}"
          continue

      safe_name_source = device_label if device_label != 'unknown_device' else ip_address or 'device'
      safe_filename = re.sub(r'[^\w.-]', '_', safe_name_source)
      backup_filename = f"{safe_filename}_{timestamp}.cfg"
      backup_path = os.path.join(backup_dir, backup_filename)

      try:
          with open(backup_path, 'w') as backup_file:
              backup_file.write(running_config)
          successful_backups[device_label] = backup_path
      except Exception as exc:
          errors[device_label] = f"Failed to write backup file: {exc}"

  result: Dict[str, Union[Dict[str, str], List[str]]] = {
      'successful_backups': successful_backups,
      'devices_not_reachable': devices_not_reachable,
  }

  if devices_auth_failed:
      result['devices_with_authentication_error'] = devices_auth_failed

  if errors:
      result['errors'] = errors

  return result

# Here starts LLM integration Logic
# ===============================================================

available_tools = [
    test_reachability,
    topology_creation,
    add_device_inventory,
    delete_device_inventory,
    load_topology,
    load_inventory,
    get_device_logs,
    configure_access_interface,
    verify_config,
    backup_device_configs
]

available_functions = {
    'test_reachability': test_reachability,
    'topology_creation': topology_creation,
    'add_device_inventory': add_device_inventory,
    'delete_device_inventory': delete_device_inventory,
    'load_inventory': load_inventory,
    'load_topology': load_topology,
    'get_device_logs': get_device_logs,
    'configure_access_interface': configure_access_interface,
    'verify_config': verify_config,
    'backup_device_configs': backup_device_configs
}
SYSTEM_PROMPT = (
    "You are a networking automation tool that must choose the right function based on the user request, "
    "and then proceed to analyze the output of the function."
)
MODEL_NAME = os.getenv("OLLAMA_MODEL", "llama3.1")


def init_messages() -> List[Dict[str, str]]:
    """Return a fresh conversation history with the system prompt."""
    return [{"role": "system", "content": SYSTEM_PROMPT}]


def generate_response(user_message: str, messages: List[Dict[str, str]]) -> tuple[str, List[Dict[str, str]]]:
    """Generate a model response, executing tool calls when requested."""
    logging.info(f"Question: {user_message}")
    messages.append({"role": "user", "content": user_message})
    response: ChatResponse = chat(MODEL_NAME, messages=messages, tools=available_tools)
    output = {}
    if response.message.tool_calls:
        for tool in response.message.tool_calls:
            if function_to_call := available_functions.get(tool.function.name):
                logging.info(f"Function called: {tool.function.name} with arguments: {tool.function.arguments}")
                output = function_to_call(**tool.function.arguments)
                logging.info(f"Function output: {output}")
        messages.append(response.message)
        messages.append({"role": "tool", "content": str(output), "tool_name": tool.function.name})
        final_response = chat(MODEL_NAME, messages=messages)
        messages.append({"role": "assistant", "content": final_response.message.content})
        logging.info(f"Answer: {final_response.message.content}")
        return final_response.message.content, messages
    messages.append({"role": "assistant", "content": response.message.content})
    logging.info(f"Answer: {response.message.content}")
    return response.message.content, messages


if __name__ == "__main__":
    messages = init_messages()
    while True:
        user_message = input("You (close the program with bye): ")
        if user_message == "bye":
            break
        reply, messages = generate_response(user_message, messages)
        print(f"[{datetime.now().isoformat()}]")
        print("Final response:", reply)
