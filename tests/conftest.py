import os
import re
import time
import json
import pprint
import pytest
import logging
import paramiko

from pathlib import Path
from scp import SCPClient
from deepdiff import DeepDiff

# Global to track file used by tests
registered_files = set()

# Global variable to track test failures
test_failed = False

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

USER = os.environ.get("USER")
ENI = "/etc/network/interfaces"
ENI_D = f"{ENI}.d"

if os.path.exists(f"/tmp/{USER}/"):
    LOCAL_DIR_FILE_TRANSLATE = f"/tmp/{USER}/"
else:
    LOCAL_DIR_FILE_TRANSLATE = "/tmp/.pytest_ifupdown2/"

os.system(f"mkdir -p {LOCAL_DIR_FILE_TRANSLATE}")


def pytest_runtest_makereport(item, call):
    global test_failed
    if call.when == "call" and call.excinfo is not None:
        test_failed = True


def assert_identical_json(json1, json2):
    """
    Compares two JSON objects using deepdiff.

    :param json1: First JSON object to compare.
    :param json2: Second JSON object to compare.
    :return: True if JSON objects are identical, False otherwise.
    """
    diff = DeepDiff(json1, json2, ignore_order=True)
    if diff:
        try:
            logger.error(f"JSON objects are not identical - deepdiff: {json.dumps(diff, indent=4)}")
        except:
            logging.error(f"JSON objects are not identical - deepdiff: {pprint.pformat(diff)}")

        assert json1 == json2


class NotEnoughPhysDevException(Exception):
    pass


class SSH(paramiko.SSHClient):
    LOCAL_COVERAGE_PATH = "tests/results/"
    REMOTE_COVERAGE_DATA_DIR = f"/tmp/.{int(time.time())}/coverage_data/"
    REMOTE_COVERAGE_DATA_PATH = f"{REMOTE_COVERAGE_DATA_DIR}.coverage"
    SWP_REGEX = re.compile("(swp_[A-Z]{2}_)", re.VERBOSE)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.swp_translated_dict = {}
        self.swp_available = []
        self.swp_reserved = []
        self.coverage_enabled = False
        self.ifreload_diff = True

    def translate_swp_xx(self, content: str, with_update: bool = False):
        update = False

        for match in self.SWP_REGEX.findall(content):
            swp = self.swp_translated_dict.get(match)
            if not swp:
                if not self.swp_available:
                    raise NotEnoughPhysDevException(
                        f"Device does not have enough physical ports (swp) for this test - {self.swp_translated_dict}"
                    )
                swp = self.swp_available[0]
                del self.swp_available[0]
                self.swp_translated_dict[match] = swp

            content = content.replace(match, swp)
            update = True

        if with_update:
            return update, content
        else:
            return content

    def __get_tmp_translated_file(self, path: str) -> str:
        with open(path, "r") as f:
            content = f.read()

        update, content = self.translate_swp_xx(content, with_update=True)

        if update:
            tmp_path = Path(f"{LOCAL_DIR_FILE_TRANSLATE}/{Path(path).name}")

            with open(tmp_path, "w") as f:
                f.write(content)
            return str(tmp_path)
        else:
            return path

    def mkdir_coverage(self):
        self.run(f"mkdir -p {self.REMOTE_COVERAGE_DATA_DIR}")

    def scp(self, source: str, destination: str):
        tmp_file = self.__get_tmp_translated_file(source)

        logger.info(f"scp {source} {destination}")

        assert os.path.exists(tmp_file), f"{tmp_file} does not exists"
        assert os.access(tmp_file, os.R_OK), f"{tmp_file} cannot be read"

        with SCPClient(self.get_transport()) as session:
            session.put(tmp_file, destination)
            registered_files.add(source)

    def run(self, cmd: str):
        translated_cmd = self.translate_swp_xx(cmd)
        logger.debug(f"[ssh] {translated_cmd}")

        stdin, stdout, stderr = self.exec_command(translated_cmd)
        exit_status = stdout.channel.recv_exit_status()
        logger.info(f"[ssh][exit {exit_status}] {translated_cmd}")

        return stdin, stdout, stderr, exit_status

    def run_assert_success(self, cmd: str):
        _, stdout, stderr, exit_status = self.run(cmd)

        assert exit_status == 0
        assert not stderr.read().decode("utf-8"), f"{cmd} has stderr"

        return stdout.read().decode("utf-8")

    def assert_interface_admin_up(self, ifname: str):
        flags = json.loads(
            self.run_assert_success(f"ip -j link show {ifname}")
        )[0].get("flags", [])
        assert "UP" in flags, f"{ifname} is administratively down: {flags}"

    def assert_interface_admin_down(self, ifname: str):
        flags = json.loads(
            self.run_assert_success(f"ip -j link show {ifname}")
        )[0].get("flags", [])
        assert "UP" not in flags, f"{ifname} is administratively up: {flags}"

    def __ifupdown2(
            self,
            op: str,
            args: str,
            expected_status: int = 0,
            return_stderr: bool = False,
            return_stdout: bool = False,
            ignore_stdout: bool = False,
            ignore_stderr: bool = False,
    ):

        assert op in ["ifup", "ifdown", "ifreload", "ifquery"]
        assert args, f"{op} has been called without arguments"

        if self.coverage_enabled:
            _, stdout, stderr, exit_status = self.run(
                f"python3 -m coverage run --data-file={self.REMOTE_COVERAGE_DATA_PATH} -a /usr/sbin/{op} {args}"
            )
        else:
            _, stdout, stderr, exit_status = self.run(f"{op} {args}")

        stdout_str: str = stdout.read().decode("utf-8")
        stderr_str: str = stderr.read().decode("utf-8")

        assert exit_status == expected_status, f"{op} exited {exit_status} (expected {expected_status}) (stdout: {repr(stdout_str)}, stderr: {repr(stderr_str)})"

        if return_stdout:
            if not ignore_stderr:
                assert not stderr_str, f"{op} has stderr ({repr(stderr_str)})"
            return stdout_str

        if not ignore_stdout:
            assert not stdout_str, f"{op} has stdout ({repr(stdout_str)})"

        if return_stderr:
            return stderr_str

        if not ignore_stderr:
            assert not stderr_str, f"{op} has stderr ({repr(stderr_str)})"

    def ifdown(self, args: str, **kwargs) -> str:
        assert args, "ifdown has been called without arguments"
        return self.__ifupdown2("ifdown", args, **kwargs)

    def ifdown_x_eth0_x_mgmt(self, **kwargs) -> str:
        return self.__ifupdown2("ifdown", "-a -X eth0 -X mgmt", **kwargs)

    def ifup(self, args: str, **kwargs) -> str:
        assert args, "ifup has been called without arguments"
        return self.__ifupdown2("ifup", args, **kwargs)

    def ifup_a(self, **kwargs) -> str:
        return self.__ifupdown2("ifup", "-a", **kwargs)

    def ifreload_a(self, **kwargs) -> str:
        args = "-a"

        if self.ifreload_diff:
            args += " --diff"

        return self.__ifupdown2("ifreload", args, **kwargs)

    def ifreload_av(self, **kwargs) -> str:
        """
        Run ifreload -av and return stderr
        """
        args = "-av"

        if self.ifreload_diff:
            args += " --diff"

        return self.__ifupdown2("ifreload", args, return_stderr=True, **kwargs)

    def ifquery(self, args: str, **kwargs) -> str:
        assert args, "ifquery has been called without arguments"
        return self.__ifupdown2("ifquery", args, **kwargs)

    def ifquery_c(self, args: str, **kwargs) -> str:
        return self.ifquery(f"{args} -c", return_stdout=True, **kwargs)

    def ifquery_ac(self, **kwargs) -> str:
        return self.ifquery_c("-a", **kwargs)

    def ifquery_ac_json(self, **kwargs) -> str:
        """
        Run ifquery -ac -o json and return json object
        """
        return json.loads(
            self.__ifupdown2("ifquery", "-ac -o json", return_stdout=True, **kwargs, )
        )

    def bridge_vlan_show_json(self):
        return json.loads(self.run_assert_success("bridge -c -j vlan show"))

    def download_coverage(self):
        self.run(
            f"cd {self.REMOTE_COVERAGE_DATA_DIR} && "
            f"coverage html -d . && "
            f"cd .. && "
            f"tar -czvf coverage_data.tar.gz coverage_data/"
        )

        remote_path = f"{self.REMOTE_COVERAGE_DATA_DIR}/../coverage_data.tar.gz"
        local_path = self.LOCAL_COVERAGE_PATH

        logger.info(f"[coverage] scp host:{remote_path} {local_path}")

        with SCPClient(self.get_transport()) as session:
            session.get(remote_path=remote_path, local_path=local_path)

    def load_swps(self, requested_ports):
        if self.swp_available:
            return
        _, stdout, _, _ = self.run(
            'python -c "import os, re;'
            'print(\',\'.join(sorted([dev for dev in os.listdir(\'/sys/class/net/\') '
            'if re.fullmatch(\'swp[0-9]+\', dev)])));"'
        )
        for swp in stdout.read().decode("utf-8").strip("\r\n").split(","):
            if swp:
                self.swp_available.append(swp)

        requested = [
            port.strip()
            for port in requested_ports.split(",")
            if port.strip()
        ]
        duplicates = sorted(
            port for port in set(requested)
            if requested.count(port) > 1
        )
        invalid = [
            port for port in requested
            if not re.fullmatch(r"swp[0-9]+", port)
        ]
        missing = [
            port for port in requested
            if port not in self.swp_available
        ]
        if not requested or duplicates or invalid or missing:
            raise NotEnoughPhysDevException(
                "empty=%s duplicates=%s invalid=%s missing=%s available=%s"
                % (
                    not requested,
                    duplicates,
                    invalid,
                    missing,
                    self.swp_available,
                )
            )

        _, stdout, stderr, status = self.run("ifquery -l")
        if status:
            raise NotEnoughPhysDevException(
                "cannot verify configured interfaces: %s"
                % stderr.read().decode("utf-8")
            )
        configured = set(
            stdout.read().decode("utf-8").split()
        )
        configured_ports = sorted(configured.intersection(requested))
        unsafe_ports = []
        for port in requested:
            _, _, _, status = self.run(
                "test ! -L /sys/class/net/%s/master && "
                "link_state=$(ethtool %s 2>/dev/null) && "
                "! printf '%%s\\n' \"$link_state\" "
                "| grep -q 'Link detected: yes'"
                % (port, port)
            )
            if status:
                unsafe_ports.append(port)
        if configured_ports or unsafe_ports:
            raise NotEnoughPhysDevException(
                "configured=%s active_or_enslaved=%s"
                % (configured_ports, unsafe_ports)
            )
        self.swp_available = list(requested)
        self.swp_reserved = list(requested)


@pytest.fixture(scope="session")
def ssh():
    remote_host = os.environ.get("PYTEST_REMOTE_HOST")
    remote_user = os.environ.get("PYTEST_REMOTE_USER")
    remote_pw = os.environ.get("PYTEST_REMOTE_PASSWORD")
    requested_swp_ports = os.environ.get("PYTEST_SWP_PORTS")

    if not remote_host:
        pytest.fail("Missing required PYTEST_REMOTE_HOST in env")

    if not remote_user:
        pytest.fail("Missing required PYTEST_REMOTE_USER in env")

    if not requested_swp_ports:
        pytest.fail(
            "Missing required PYTEST_SWP_PORTS allowlist "
            "(comma-separated plain physical ports)"
        )

    # Setup SSH client using paramiko
    client = SSH()
    client.load_system_host_keys()
    connect_args = {
        "hostname": remote_host,
        "username": remote_user,
    }
    if remote_pw:
        connect_args["password"] = remote_pw
    client.connect(**connect_args)
    client.load_swps(requested_swp_ports)
    client.mkdir_coverage()
    # todo: install necessary packages (i.e. coverage)
    try:
        yield client
    finally:
        coverage_root = os.path.dirname(
            client.REMOTE_COVERAGE_DATA_DIR.rstrip("/")
        )
        _, _, _, cleanup_status = client.run(
            "rm -rf %s" % coverage_root
        )
        client.close()
        if cleanup_status:
            pytest.fail(
                "failed to remove remote coverage workspace %s"
                % coverage_root
            )


@pytest.fixture(scope="session")
def preserve_device_config(ssh):
    """Restore ENI and drop-ins exactly after the integration session."""
    backup_dir = "/tmp/.ifupdown2_eni_backup_%d" % int(time.time())
    reserved_admin_up = {}
    for port in ssh.swp_reserved:
        flags = json.loads(
            ssh.run_assert_success(f"ip -j link show dev {port}")
        )[0].get("flags", [])
        reserved_admin_up[port] = "UP" in flags
    restore_reserved_ports = "".join(
        "ip link set dev %s %s && "
        % (port, "up" if admin_up else "down")
        for port, admin_up in reserved_admin_up.items()
    )
    ssh.run_assert_success(
        "mkdir -p %s/interfaces.d && "
        "cp -a %s %s/interfaces && "
        "cp -a %s/. %s/interfaces.d/"
        % (backup_dir, ENI, backup_dir, ENI_D, backup_dir)
    )

    yield backup_dir

    _, _, _, restore_status = ssh.run(
        "ifdown -a -X eth0 -X mgmt || true; "
        "cp -af %s/interfaces %s && "
        "find %s -mindepth 1 -maxdepth 1 -delete && "
        "cp -af %s/interfaces.d/. %s/ && "
        "ifreload -a && "
        "%s"
        "cmp -s %s/interfaces %s && "
        "diff -qr %s/interfaces.d %s && "
        "rm -rf %s"
        % (
            backup_dir,
            ENI,
            ENI_D,
            backup_dir,
            ENI_D,
            restore_reserved_ports,
            backup_dir,
            ENI,
            backup_dir,
            ENI_D,
            backup_dir,
        )
    )
    if restore_status:
        pytest.fail(
            "failed to restore integration ENI from %s (rc=%s)"
            % (backup_dir, restore_status)
        )


@pytest.fixture(scope="function")
def setup(request, ssh, preserve_device_config):
    ssh.ifdown_x_eth0_x_mgmt()
    file_name = request.node.name.replace("test_", "")
    ssh.scp(os.path.join("tests/eni", f"{file_name}.eni"), ENI)
    ssh.run_assert_success(
        f"find {ENI_D} -mindepth 1 -maxdepth 1 -delete"
    )
    try:
        yield
    finally:
        ssh.ifreload_diff = True
        _, _, _, cleanup_status = ssh.run(
            "ifdown -a -X eth0 -X mgmt"
        )
        if cleanup_status:
            pytest.fail(
                "function cleanup failed for %s (rc=%s)"
                % (request.node.name, cleanup_status)
            )


@pytest.fixture
def get_json(ssh):
    def _get_translated_json(file_name):
        file_path = f"tests/output/{file_name}"

        logger.info(f"get_json: {file_path}")

        with open(file_path, "r") as f:
            content = f.read()

        registered_files.add(file_path)
        return json.loads(ssh.translate_swp_xx(content))

    yield _get_translated_json


@pytest.fixture
def get_file(ssh):
    def _get_translated_file(file_name):
        file_path = f"tests/output/{file_name}"

        logger.info(f"get_file: {file_path}")

        with open(file_path, "r") as f:
            content = f.read()

        registered_files.add(file_path)
        return ssh.translate_swp_xx(content)

    yield _get_translated_file


@pytest.fixture
def skip_if_any_test_failed(request):
    global test_failed
    if test_failed:
        pytest.skip("skipping this test because a previous test failed")
