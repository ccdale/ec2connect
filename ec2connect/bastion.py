import sys
import os
import time
import subprocess
import requests
import snlogs.sntunnel as SNT
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from botocore.exceptions import ClientError

hangingline = False


class bcolours:
    HEADER = "\033[35m"
    OKBLUE = "\033[34m"
    OKGREEN = "\033[32m"
    WARNING = "\033[33m"
    FAIL = "\033[31m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"


def mopf():
    global hangingline
    print(f"{bcolours.FAIL}[FAIL]{bcolours.ENDC}")
    hangingline = False


def mopd():
    global hangingline
    print(f"{bcolours.OKGREEN}[DONE]{bcolours.ENDC}")
    hangingline = False


def mop(msg):
    global hangingline
    print(f"{msg:<74}", end="", flush=True)
    hangingline = True


def mopp(msg):
    global hangingline
    if hangingline:
        print()
        hangingline = False
    print(msg)


def iidState(cfg, iid):
    inst = cfg["resource"].Instance(iid)
    return inst.state


def waitBastionStart(iid, cfg, iter=12):
    thestate = iidState(cfg, iid)
    cn = 0
    while thestate["Code"] != 16:
        time.sleep(5)
        thestate = iidState(cfg, iid)
        cn += 1
        if cn > iter:
            break
    return True if int(thestate["Code"]) == 16 else False


def doStopBastion(cfg):
    # if SNT.isTunnelUp(cfg):
    #     SNT.killSsh(cfg)
    SNT.clearSecurityGroup(cfg)
    bid = [bastionId(cfg)]
    resp = cfg["resource"].instances.filter(InstanceIds=bid).terminate()
    if len(resp) and "TerminatingInstances" in resp[0]:
        ti = resp[0]["TerminatingInstances"]
        if len(ti) and "CurrentState" in ti[0]:
            cs = ti[0]["CurrentState"]
            stcode = cs["Code"]
            if stcode == 32:
                mopp("Bastion {} is shutting down".format(bid))
                return True
    mopp("Failed to terminate bastion {}".format(bid))


def doStartBastion(cfg, myip):
    try:
        running = False
        iid = None
        mop("Starting Bastion ...")
        resp = cfg["client"].run_instances(
            LaunchTemplate={"LaunchTemplateName": cfg["ltname"]}, MaxCount=1, MinCount=1
        )
        # print(resp)
        if "Instances" in resp and len(resp["Instances"]) > 0:
            iid = resp["Instances"][0]["InstanceId"]
        if iid is not None:
            mopd()
            mop("Waiting for running state")
            running = waitBastionStart(iid, cfg)
            mopd()
            try:
                mop("allowing my ip: {}".format(myip))
                SNT.allowMyIp(cfg, myip)
                mopd()
            except ClientError:
                # access already allowed
                mopd()
            mop("Setting up SSH connections")
            cok, keyfn = setupConnect(cfg, iid, True)
            if cok:
                mopd()
                inst = cfg["resource"].Instance(iid)
                iip = inst.public_ip_address
                mop("Waiting for SSHd to start on bastion (about 20 seconds)")
                if SNT.waitForSSH(iip, cfg["sshuser"], keyfn):
                    mopd()
                else:
                    mopf()
                    raise (Exception("Gave up waiting for SSHd to start on Bastion"))
            else:
                mopf()
                mopp("failed to setupConnect")
        else:
            mopf()
            mopp("Failed to start Bastion")
        return running
    except Exception as e:
        mopp(f"Exception: {e}")
        return False


def isBastionUp(cfg):
    mop("getting bastion instance id")
    iid = bastionId(cfg)
    mopd()
    # print("instance id: {}".format(iid))
    return False if iid is None else True


def bastionId(cfg):
    iid = None
    filters = [{"Values": [cfg["instname"]], "Name": "tag:Name"}]
    resp = cfg["client"].describe_instances(Filters=filters)
    if "Reservations" in resp and len(resp["Reservations"]):
        for rsvs in resp["Reservations"]:
            if "Instances" in rsvs and len(rsvs["Instances"]):
                instances = rsvs["Instances"]
                for instance in instances:
                    inst = cfg["resource"].Instance(instance["InstanceId"])
                    # 48 is a terminated instance and should be ignored
                    if inst.state["Code"] < 17:
                        iid = instance["InstanceId"]
                        break
                if iid is not None:
                    break
    return iid


def tmpKey(hide=False):
    keyname = "tmpbastion-" + os.environ["USER"]
    keyfn = "/".join([os.environ["HOME"], ".ssh", keyname])
    key = rsa.generate_private_key(
        backend=crypto_default_backend(), public_exponent=65537, key_size=2048
    )
    private_key = key.private_bytes(
        crypto_serialization.Encoding.PEM,
        crypto_serialization.PrivateFormat.PKCS8,
        crypto_serialization.NoEncryption(),
    )
    public_key = key.public_key().public_bytes(
        crypto_serialization.Encoding.OpenSSH, crypto_serialization.PublicFormat.OpenSSH
    )
    with open(keyfn, "w") as kfn:
        kfn.write(private_key.decode())
    os.chmod(keyfn, 0o600)
    if not hide:
        mopp("temporary keys generated")
    return [keyfn, public_key.decode()]


def setupConnect(cfg, iid, hide=False):
    try:
        keyfn, pubkey = tmpKey(hide)
        resp = cfg["ec2connect"].send_ssh_public_key(
            InstanceId=iid,
            InstanceOSUser=cfg["sshuser"],
            AvailabilityZone="eu-west-1a",
            SSHPublicKey=pubkey,
        )
        return (resp["Success"], keyfn)
    except Exception as e:
        mopp(f"setupConnect: {e}")


def doScpCmd(cfg, filename):
    try:
        iid = bastionId(cfg)
        if iid is not None:
            success, keyfn = setupConnect(cfg, iid, True)
            if success:
                inst = cfg["resource"].Instance(iid)
                instanceip = inst.public_ip_address
                cmd = SNT.buildScpCmd(instanceip, cfg["sshuser"], filename, keyfn=keyfn)
                res = subprocess.run(cmd, capture_output=True)
                return res
            else:
                mopp("Failed to connect")
        else:
            mopp("Failed to get bastion iid")
    except Exception as e:
        mopp(f"Except: {e}")


def doSSHCmd(cfg, icmd):
    try:
        iid = bastionId(cfg)
        if iid is not None:
            success, keyfn = setupConnect(cfg, iid, True)
            if success:
                inst = cfg["resource"].Instance(iid)
                instanceip = inst.public_ip_address
                cmd = SNT.buildSshCmd(instanceip, cfg["sshuser"], keyfn=keyfn)
                cmd.extend(icmd)
                res = subprocess.run(cmd, capture_output=True)
                # print(f"return code: {res.returncode}")
                # print(f"stdout: {res.stdout.decode()}")
                # print(f"stderr: {res.stderr.decode()}")
                return res
            else:
                mopp("Failed to connect")
        else:
            mopp("Failed to get bastion iid")
    except Exception as e:
        mopp(f"Except: {e}")


def activityMarker(cfg):
    iid = bastionId(cfg)
    success, keyfn = setupConnect(cfg, iid, hide=True)
    if success:
        inst = cfg["resource"].Instance(iid)
        instanceip = inst.public_ip_address
        cmd = SNT.buildSshCmd(instanceip, cfg["sshuser"], keyfn=keyfn)
        cmd.append("touch")
        cmd.append(f"""/home/{cfg["sshuser"]}/activity""")
        subprocess.run(cmd, stderr=subprocess.DEVNULL)


def bastionSSHTunnel(cfg):
    iid = bastionId(cfg)
    success, keyfn = setupConnect(cfg, iid)
    if success:
        print("temporary key installed")
        inst = cfg["resource"].Instance(iid)
        instanceip = inst.public_ip_address
        print("bastion IP {}".format(instanceip))
        SNT.waitForSSH(instanceip, cfg["sshuser"], keyfn)
        cmd = SNT.buildSshCmd(instanceip, cfg["sshuser"], cfg["dbname"], keyfn)
        subprocess.run(cmd, stderr=subprocess.DEVNULL)
        if SNT.isTunnelUp(cfg):
            print("bastion ssh tunnel started")
        else:
            print("bastion tunnel failed to start")
    else:
        print("Failed to send key to bastion.")


def checkBastion(cfg):
    r = requests.get("http://ipecho.net/plain")
    myip = r.text
    if not isBastionUp(cfg):
        if doStartBastion(cfg, myip):
            # print("Bastion is running")
            pass
    try:
        mop("allowing my ip: {}".format(myip))
        SNT.allowMyIp(cfg, myip)
        mopd()
    except ClientError:
        mopd()
        # print("IP address is already allowed ingress")
        pass
    # print("Bastion started and my ip allowed")
    # as tunnel bastionSSHTunnel(cfg)
