"""Python client for the MPSI PsiService."""

import grpc
from .generated import psi_service_pb2
from .generated import psi_service_pb2_grpc
from .generated import common_pb2


class PsiClient:
    """Client for submitting input sets to a PSI party's PsiService."""

    def __init__(self, target: str, *, tls: bool = False,
                 ca_cert: str | None = None,
                 client_cert: str | None = None,
                 client_key: str | None = None):
        """
        Connect to a party's PsiService.

        Args:
            target: gRPC target address (e.g. "localhost:50090")
            tls: Enable TLS
            ca_cert: Path to CA certificate (PEM)
            client_cert: Path to client certificate (PEM) for mTLS
            client_key: Path to client private key (PEM) for mTLS
        """
        options = [("grpc.enable_http_proxy", 0)]
        if tls:
            ca = open(ca_cert, "rb").read() if ca_cert else None
            cert = open(client_cert, "rb").read() if client_cert else None
            key = open(client_key, "rb").read() if client_key else None
            creds = grpc.ssl_channel_credentials(ca, key, cert)
            self.channel = grpc.secure_channel(target, creds, options=options)
        else:
            self.channel = grpc.insecure_channel(target, options=options)

        self.stub = psi_service_pb2_grpc.PsiServiceStub(self.channel)

    def compute_intersection(
        self,
        elements: list[str],
        *,
        role: str = "member",
        leader_address: str = "",
        protocol: str = "ks05_t_mpsi",
        num_parties: int = 3,
        threshold: int = 3,
        timeout: float | None = None,
    ) -> tuple[list[str], str]:
        """
        Submit input set and wait for intersection result.

        Args:
            elements: Input set elements (strings)
            role: Party role - "leader" or "member"
            leader_address: Inter-party address of the leader (required)
            protocol: Protocol identifier
            num_parties: Number of participating parties
            threshold: Intersection threshold
            timeout: RPC timeout in seconds

        Returns:
            (intersection, status_message) tuple.
            intersection is non-empty only for the leader party.
        """
        role_map = {
            "member": psi_service_pb2.MEMBER,
            "leader": psi_service_pb2.LEADER,
            "dealer": psi_service_pb2.DEALER,
        }
        request = psi_service_pb2.ComputeRequest(
            protocol=protocol,
            num_parties=num_parties,
            threshold=threshold,
            elements=elements,
            role=role_map[role],
            leader_address=leader_address,
        )

        response = self.stub.ComputeIntersection(request, timeout=timeout)

        intersection = list(response.intersection)
        status_msg = response.status.message if response.status else ""

        if response.status and response.status.code != common_pb2.STATUS_OK:
            raise RuntimeError(f"PSI error: {status_msg}")

        return intersection, status_msg

    def compute_intersection_from_file(
        self,
        input_file: str,
        **kwargs,
    ) -> tuple[list[str], str]:
        """
        Read elements from a file (one per line) and compute intersection.

        Args:
            input_file: Path to file with one element per line
            **kwargs: Passed to compute_intersection (role, leader_address, etc.)

        Returns:
            (intersection, status_message) tuple.
        """
        with open(input_file) as f:
            elements = [line.strip() for line in f if line.strip()]
        return self.compute_intersection(elements, **kwargs)

    def close(self):
        """Close the gRPC channel."""
        self.channel.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
