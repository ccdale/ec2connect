"""ssh tunnel specific routines"""

import os
import requests
import time
import subprocess
from botocore.exceptions import ClientError


class TunnelFailed(Exception):
    pass


sshpidfn = "/var/tmp/mcu.pid"


def getInstanceId(cfg):
    """
    retrieves the instance id from AWS
    """
    iid = None
    filters = [{"Values": [cfg["InstanceName"]], "Name": "tag:Name"}]
    resp = cfg["client"].describe_instances(Filters=filters)
    if "Reservations" in resp:
        if "Instances" in resp["Reservations"][0]:
            if "InstanceId" in resp["Reservations"][0]["Instances"][0]:
                iid = resp["Reservations"][0]["Instances"][0]["InstanceId"]
    return iid


def startinstance(cfg):
    """
    issues the start instance command
    """
    try:
        iid = getInstanceId(cfg)
        if iid is not None:
            cfg["client"].start_instances(InstanceIds=[iid])
    except Exception as e:
        print("An error occurred starting the instance")
        msg = "{}: {}".format(type(e).__name__, e)
        print(msg)


def stopinstance(cfg):
    """
    issues the stop instance command
    """
    try:
        iid = getInstanceId(cfg)
        if iid is not None:
            cfg["client"].stop_instances(InstanceIds=[iid])
    except Exception as e:
        print("An error occurred stopping the instance")
        msg = "{}: {}".format(type(e).__name__, e)
        print(msg)


def instanceState(cfg):
    """
    return the state of the instance as a dict
    {"Code": 80, "Name": "stopped"}
    {"Code": 16, "Name": "running"}
    """
    try:
        iid = getInstanceId(cfg)
        if iid is not None:
            inst = cfg["resource"].Instance(iid)
            return inst.state
    except Exception as e:
        print("An error occurred obtaining the instance state")
        msg = "{}: {}".format(type(e).__name__, e)
        print(msg)


def waitForState(state, cfg, iter=12):
    """
    wait for the instance to achieve the desired state
    returns True if it does, False otherwise
    """
    thestate = instanceState(cfg)
    code = thestate["Code"]
    cn = 0
    while code != state:
        time.sleep(5)
        thestate = instanceState(cfg)
        code = thestate["Code"]
        cn = cn + 1
        if cn > iter:
            break
    return True if code == state else False


def waitForPendStop(cfg):
    """
    function to wait until the instance is either fully started or stopped
    if it timesout (default 1 minute) then an exception is raised and the
    script ends
    """
    thestate = instanceState(cfg)
    code = thestate["Code"]
    if code == 0:
        # pending
        st = waitForState(16, cfg)
        if not st:
            raise Exception("instance failed to achieve a running state")
    elif code == 64:
        # stopping
        st = waitForState(80, cfg)
        if not st:
            raise Exception("instance failed to achieve a stopped state")
    return True


def __waitInstance(cfg, state):
    waitForPendStop(cfg)
    thestate = instanceState(cfg)
    code = thestate["Code"]
    if code != state:
        startinstance(cfg) if state == 16 else stopinstance(cfg)
    return waitForState(state, cfg)


def waitStartInstance(cfg):
    if not __waitInstance(cfg, 16):
        raise Exception("Failed to start instance")
    else:
        print("Instance has started.")


def waitStopInstance(cfg):
    if not __waitInstance(cfg, 80):
        raise Exception("Failed to stop instance")
    else:
        print("Instance has stopped.")


def statusSecurityGroup(cfg):
    # print(f"""getting group status for {cfg["sgrp"]}""")
    thisipr, thisperm, sgr = _sgStatus(cfg)
    # print(f"status: {thisperm} {thisipr} {sgr}")
    if thisperm is not None and thisipr is not None:
        print("{} does have access to the security group".format(cfg["sgdesc"]))
    else:
        print(
            "{} does not currently have access to the security group".format(
                cfg["sgdesc"]
            )
        )


def clearSecurityGroup(cfg):
    thisipr, thisperm, sgr = _sgStatus(cfg)
    if thisperm is not None and thisipr is not None:
        thisperm["IpRanges"] = [thisipr]
        # print("Removing security group access for {}".format(cfg["sgdesc"]))
        sgr.revoke_ingress(GroupId=cfg["sgrp"], IpPermissions=[thisperm])
    # else:
    # print(
    #     "{} does not currently have access to the security group".format(
    #         cfg["sgdesc"]
    #     )
    # )


def _sgStatus(cfg):
    sgr = cfg["resource"].SecurityGroup(cfg["sgrp"])
    perms = sgr.ip_permissions
    thisipr = None
    thisperm = None
    if len(perms) > 0:
        for perm in perms:
            if "IpRanges" in perm:
                for ipr in perm["IpRanges"]:
                    if "Description" in ipr and ipr["Description"] == cfg["sgdesc"]:
                        thisipr = ipr
                        thisperm = perm
    return [thisipr, thisperm, sgr]


def allowMyIp(cfg, myip):
    sgr = cfg["resource"].SecurityGroup(cfg["sgrp"])
    perms = {
        "FromPort": 22,
        "ToPort": 22,
        "IpProtocol": "tcp",
        "IpRanges": [{"CidrIp": myip + "/32", "Description": cfg["sgdesc"]}],
    }
    sgr.authorize_ingress(IpPermissions=[perms])


def tunnelPid(cfg):
    pid = None
    dbn = "[" + cfg["dbname"][:1] + "]" + cfg["dbname"][1:12]
    try:
        ps = subprocess.Popen(["pgrep", "-f", dbn], stdout=subprocess.PIPE)
        # gp = subprocess.Popen(['grep', dbn], stdin=ps.stdout, stdout=subprocess.PIPE)
        # sp = subprocess.Popen(['sed', r's/[ \t]\+/ /g'], stdin=gp.stdout, stdout=subprocess.PIPE)
        # cp = subprocess.Popen(['cut', '-d', ' ', '-f', '2'], stdin=sp.stdout, stdout=subprocess.PIPE)
        pid = int(ps.stdout.read().decode("utf-8").strip())
        print("tunnel pid: {}".format(pid))
    except ValueError:
        pass
    return pid


def isTunnelUp(cfg):
    pid = tunnelPid(cfg)
    ret = True if pid is not None else False
    return ret


def killSsh(cfg):
    pid = tunnelPid(cfg)
    if pid is not None:
        cmd = ["kill", str(pid)]
        op = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if op.returncode == 0:
            print("SSH tunnel shutdown.")
        else:
            print("ERROR: ssh kill returned {}".format(op.stderr))
    else:
        print("SSH tunnel is not up")


def buildScpCmd(iip, sshuser, filename, keyfn=None):
    timeout = "10"
    cmd = [
        "scp",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "ConnectTimeout=" + timeout,
    ]
    if keyfn is not None:
        cmd.append("-i")
        cmd.append(keyfn)
    cmd.append(f"{sshuser}@{iip}:{filename}")
    cmd.append("./")
    return cmd


def buildSshCmd(iip, sshuser, dbhost=None, keyfn=None):
    timeout = "2" if dbhost is None else "10"
    cmd = [
        "ssh",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "ConnectTimeout=" + timeout,
    ]
    if keyfn is not None:
        cmd.append("-i")
        cmd.append(keyfn)
    if os.environ["USER"] != sshuser:
        cmd.append("-l")
        cmd.append(sshuser)
    if dbhost is not None:
        cmd.append("-L")
        cmd.append("3306:" + dbhost + ":3306")
        cmd.append("-f")
        cmd.append("-N")
    cmd.append(iip)
    return cmd


def waitForSSH(iip, sshusr, keyfn=None):
    cmd = buildSshCmd(iip, sshusr, keyfn=keyfn)
    cmd.extend(["which", "star"])
    cn = 0
    connected = False
    while not connected:
        op = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # print(f"rc: {op.returncode}, {op.stdout.decode()}")
        # print(" . ", end="", flush=True)
        if op.returncode == 0:
            # print("[DONE]")
            connected = True
            break
        cn = cn + 1
        if cn > 30:
            # print("\nERROR: Gave up waiting for SSHD to start")
            break
        time.sleep(1)
    return connected


def startSSH(iip, sshusr, dbhost):
    if waitForSSH(iip, sshusr):
        print("Establishing ssh tunnel to db")
        cmd = buildSshCmd(iip, sshusr, dbhost)
        subprocess.run(cmd)
    else:
        print("SSHD is still not running, you may feel you need to have a rummage")


def doStartSSH(cfg):
    try:
        iid = getInstanceId(cfg)
        inst = cfg["resource"].Instance(iid)
        instanceip = inst.public_ip_address
        print("instance ip: {}".format(instanceip))
        startSSH(instanceip, cfg["sshuser"], cfg["dbname"])
    except Exception as e:
        msg = "A doStartSSH error occurred: {}: {}".format(type(e).__name__, e)
        print("{}: {}".format(msg, e))


def doStartTunnel(cfg):
    try:
        r = requests.get("http://ipecho.net/plain")
        myip = r.text
        print("allowing my ip: {}".format(myip))
        allowMyIp(cfg, myip)
    except ClientError:
        print("IP address is already allowed ingress")
    except Exception as e:
        print("An error occured allowing ip {}: {}".format(myip, e))
    try:
        print("starting instance ...")
        waitStartInstance(cfg)
        doStartSSH(cfg)
        if isTunnelUp(cfg):
            print("Tunnel has started.")
        else:
            raise TunnelFailed("Failed to start tunnel.")
    except Exception as e:
        msg = "A doStartTunnel error occurred: {}: {}".format(type(e).__name__, e)
        print("{}: {}".format(msg, e))
        print("An error occured: {}".format(e))


def doStopTunnel(cfg):
    killSsh(cfg)
    clearSecurityGroup(cfg)


def doStopInstance(cfg):
    doStopTunnel(cfg)
    print("Stopping instance ...")
    waitStopInstance(cfg)


def statusTunnel(cfg):
    statusSecurityGroup(cfg)
    if isTunnelUp(cfg):
        print("The SSH tunnel is up")
    else:
        print("The SSH tunnel is down")


def checkTunnel(cfg):
    if not isTunnelUp(cfg):
        doStartTunnel(cfg)
