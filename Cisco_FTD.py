from fastapi import FastAPI,HTTPException
import requests
app = FastAPI()

#GET TOKEN

@app.post("/get_token")
def get_token(username: str, password: str):
    url = "https://10.10.20.65/api/fdm/latest/fdm/token"
    payload = {
        "grant_type": "password",
        "username": "admin",
        "password": "Sbxftd1234!",
        "desired_expires_in": 34128000
    }
    response = requests.post(url, json=payload, verify=False)
    return response.json()

#GET NETWORK OBJECTS

@app.get("/get_network")
def get_network(token: str ):
    url = "https://10.10.20.65/api/fdm/latest/object/networks"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}"
    }
    response = requests.get(url, headers=headers, verify=False)
    return response.json()

#POST THE NETWORK OBJECT

@app.post("/create_network_object")
def create_network_object(token: str, network_data: dict):
      url = "https://10.10.20.65/api/fdm/latest/object/networks"
      headers = {
             "Content-Type": "application/json",
             "Authorization": f"Bearer {token}"
      }
      response = requests.post(url, json=network_data, headers=headers, verify=False)
      if response.status_code == 200:
             return {"message": "Network object created successfully"}
      else:
             return {"error": "Unable to create network object"}

# UPDATE THE NETWORK OBJECT

@app.put('/network-objects/{object_id}')
def update_network_object(token: str ,object_id: str, network_object_data: dict):
    network_object_url = f'https://10.10.20.65/api/fdm/latest/object/networks/bbbd2025-1ee2-11ee-b901-d724a5e9e2c2'
    headers= {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {object_id}",
        "Authorization": f"Bearer {token}"
    }
    response = requests.put(network_object_url, json=network_object_data, headers=headers, verify=False)
    return response.json()

#DELETE THE NETWORK OBJECT

@app.delete('/network-objects/{object_id}')
def delete_network_object(token:str ,object_id: str):
    network_object_url = f'https://10.10.20.65/api/fdm/latest/object/networks/{object_id}'
    headers =  {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {object_id}",
        "Authorization": f"Bearer {token}"
    }
    response = requests.delete(network_object_url, headers=headers, verify=False)
    if response.status_code == 204:
        return {'message': 'Network object deleted successfully'}
    else:
        return {'error': 'Failed to delete network object'}

# GET PORT OBJECTS

@app.get('/get_port-object')
def get_port_object(token:str):
    url = f'https://10.10.20.65/api/fdm/latest/object/tcpports'
    headers ={
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}"
    }
    response = requests.get(url, headers=headers, verify=False)
    return response.json()

#POST PORT OBJECTS

@app.post('/port-objects')
def create_port_object(token:str,port_object_data: dict):
    url = f'https://10.10.20.65/api/fdm/latest/object/tcpports'
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}"
    }
    response = requests.post(url, json=port_object_data, headers=headers, verify=False)
    return response.json()

#UPDATE THE PORT OBJECT

@app.put('/port-objects/{port_object_id}')
def update_port_object(token:str,port_object_id: str, port_object_data: dict):
    port_object_url = f'https://10.10.20.65/api/fdm/latest/object/tcpports/{port_object_id}'
    headers ={
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}"
    }
    response = requests.put(port_object_url, json=port_object_data, headers=headers, verify=False)
    return response.json()

#DELETE THE PORT OBJECTS

@app.delete('/port-objects/{port_object_id}')
def delete_network_object(token:str,port_object_id: str):
    port_object_url = f'https://10.10.20.65/api/fdm/latest/object/tcpports/{port_object_id}'
    headers =  {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {port_object_id}",
        "Authorization": f"Bearer {token}"
    }
    response = requests.delete(port_object_url, headers=headers, verify=False)
    if response.status_code == 204:
        return {'message': 'port object deleted successfully'}
    else:
        return {'error': 'Failed to delete port object'}

#GET THE ACCESS RULE PARENT ID

@app.get("/access_rules")
def get_access_rules(token: str):
       url = "https://10.10.20.65/api/fdm/v6/policy/accesspolicies"
       headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {token}"
       }
       response = requests.get(url, headers=headers, verify=False)
       return response.json()

#GET ACCESS RULE

@app.get("/accesspolicy/{Parent_id}/access_rules")
def get_access_rules(token:str,Parent_id:str):
       url = f'https://10.10.20.65/api/fdm/latest/policy/accesspolicies/{Parent_id}/accessrules'
       headers = {
                  "Content-Type": "application/json",
                  "Authorization": f"Bearer {token}",
                  "Parent_id": f"{Parent_id}"
       }
       response = requests.get(url, headers=headers,verify=False)
       return response.json()

#POST THE ACCESS RULE

@app.post('/accesspolicy/{Parent_id}/accessrules')
def create_access_policy(token:str,Parent_id:str,access_policy_data: dict):
    access_policy_url = f'https://10.10.20.65/api/fdm/latest/policy/accesspolicies/{Parent_id}/accessrules'
    headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {token}",
                "Parent_id": f"{Parent_id}"
       }
    response = requests.post(access_policy_url, json=access_policy_data, headers=headers, verify=False)
    if response.status_code == 200:
        return response.json()
    else:
        raise HTTPException(status_code=response.status_code, detail=response.text)

#UPDATE THE ACCESS RULE

@app.put('/accesspolicies/{access_policy_id}/accessrules')
def update_access_policy(token:str,access_policy_id: str,Parent_id:str, access_policy_data: dict):
    access_policy_url = f"https://10.10.20.65/api/fdm/v6/policy/accesspolicies/c78e66bc-cb57-43fe-bcbf-96b79b3475b3/accessrules/50011856-213b-11ee-b1c5-ff3c88952d7e"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
        "Parent_id": f"{Parent_id}",
        "access_policy_id": f"{access_policy_id}"
    }
    response = requests.put(access_policy_url, json=access_policy_data, headers=headers, verify=False)
    return response.json()

#DELETE THE ACCESS RULE

@app.delete('/accesspolicies/{access_policy_id}/accessrules')
def delete_access_policy(token:str,access_policy_id: str,Parent_id:str):
    url = f'https://10.10.20.65/api/fdm/v6/policy/accesspolicies/{Parent_id}/accessrules/{access_policy_id}'
    headers =  {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
        "Parent_id": f"{Parent_id}",
        "access_policy_id": f"{access_policy_id}"
    }
    response = requests.delete(url, headers=headers, verify=False)
    if response.status_code == 204:
        return {'message': 'accesspolicy deleted successfully'}
    else:
        return {'error': 'Failed to delete accesspolicy'}

    return response


#AUTO_NAT_POLICY

# GET THE PARENT ID

@app.get("/nat_rules")
def nat_rules(token: str):
       url = "https://10.10.20.65/api/fdm/v6/policy/objectnatpolicies"
       headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {token}"
       }
       response = requests.get(url, headers=headers, verify=False)
       return response.json()

#POST THE AUTO_NAT_POLICY

@app.post('/objectnatpolicy/{Parent_id}/objectnatrules')
def create_nat_policy(token:str,Parent_id:str,nat_policy_data: dict):
    nat_policy_url = f'https://10.10.20.65/api/fdm/v6/policy/objectnatpolicies/{Parent_id}/objectnatrules'
    headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {token}",
                "Parent_id": f"{Parent_id}"
       }
    response = requests.post(nat_policy_url, json=nat_policy_data, headers=headers, verify=False)
    if response.status_code == 200:
        return response.json()
    else:
        raise HTTPException(status_code=response.status_code, detail=response.text)

# GET THE AUTO_NAT_POLICY

@app.get("/objectnatpolicy/{Parent_id}/objectnatrules")
def get_nat_rules(token:str,Parent_id:str):
       url = f'https://10.10.20.65/api/fdm/v6/policy/objectnatpolicies/{Parent_id}/objectnatrules'
       headers = {
                  "Content-Type": "application/json",
                  "Authorization": f"Bearer {token}",
                  "Parent_id": f"{Parent_id}"
       }
       response = requests.get(url, headers=headers,verify=False)
       return response.json()

#UPDATE THE AUTO_NAT_POLICY

@app.put('/objectnatpolicy/{Parent_id}/objectnatrules')
def update_nat_policy(token:str,nat_policy_id: str,Parent_id:str, nat_policy_data: dict):
    nat_policy_url = f"https://10.10.20.65/api/fdm/v6/policy/objectnatpolicies/{Parent_id}/objectnatrules/{nat_policy_id}"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
        "Parent_id": f"{Parent_id}",
        "access_policy_id": f"{nat_policy_id}"
    }
    response = requests.put(nat_policy_url, json=nat_policy_data, headers=headers, verify=False)
    return response.json()

#DELETE THE AUTO_NAT_POLICY

@app.delete('/objectnatpolicy/{Parent_id}/objectnatrules')
def delete_nat_policy(token:str,nat_policy_id: str,Parent_id:str):
    url = f'https://10.10.20.65/api/fdm/v6/policy/objectnatpolicies/{Parent_id}/objectnatrules/{nat_policy_id}'
    headers =  {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
        "Parent_id": f"{Parent_id}",
        "access_policy_id": f"{nat_policy_id}"
    }
    response = requests.delete(url, headers=headers, verify=False)
    if response.status_code == 204:
        return {'message': 'NATpolicy deleted successfully'}
    else:
        return {'error': 'Failed to delete NATpolicy'}

#GET THE MANUAL NAT POLICY

@app.get("/manualnatpolicy")
def nat_rules(token: str):
       url = "https://10.10.20.65/api/fdm/v6/policy/manualnatpolicies"
       headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {token}"
       }
       response = requests.get(url, headers=headers, verify=False)
       return response.json()

# POST THE MANUAL NAT POLICY

@app.post('/manualnatpolicy/{Parent_id}/manualnatrules')
def create_nat_policy(token:str,Parent_id:str,nat_policy_data: dict):
    nat_policy_url = f'https://10.10.20.65/api/fdm/v6/policy/manualnatpolicies/{Parent_id}/manualnatrules'
    headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {token}",
                "Parent_id": f"{Parent_id}"
       }
    response = requests.post(nat_policy_url, json=nat_policy_data, headers=headers, verify=False)
    if response.status_code == 200:
        return response.json()
    else:
        raise HTTPException(status_code=response.status_code, detail=response.text)

#GET THE MANUALNATPOLICY

@app.get("/manualnatpolicy/{Parent_id}/manualnatrules")
def get_nat_rules(token:str,Parent_ijd:str):
       url = f'https://10.10.20.65/api/fdm/v6/policy/manualnatpolicies/{Parent_id}/manualnatrules'
       headers = {
                  "Content-Type": "application/json",
                  "Authorization": f"Bearer {token}",
                  "Parent_id": f"{Par
       ent_id}"
       }
       response = requests.get(url, headers=headers,verify=False)
       return response.json()
  
#UPDATE THE MANUAL NAT POLICY

@app.put('/manualnatpolicy/{Parent_id}/manualnatrules')
 update_nat_policy(token:str,nat_policy_id: str,Parent_id:str, nat_policy_data: dict):
    nat_policy_url = f"https://10.10.20.65/api/fdm/v6/policy/manualnatpolicies/{Parent_id}/manualnatrules/{nat_policy_id}"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
        "Parent_id": f"{Parent_id}",
        "access_policy_id": f"{nat_policy_id}"
    }
    response = requests.put(nat_policy_url, json=nat_policy_data, headers=headers, verify=False)
    return response.json()

#DELETE THE MANUAL NAT POLICY

@app.delete('/manualnatpolicy/{Parent_id}/manualnatrules')
def delete_nat_policy(token:str,nat_policy_id: str,Parent_id:str):
    url = f''
    headers =  {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
        "Parent_id": f"{Parent_id}",
        "access_policy_id": f"{nat_policy_id}"
    }
    response = requests.delete(url, headers=headers, verify=False)
    if response.status_code == 204:
        return {'message': 'NATpolicy deleted successfully'}
    else:
        return {'error': 'Failed to delete NATpolicy'}
    
