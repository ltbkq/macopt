"""macopt — VMware Workstation macOS guest optimizer.

macopt only ever writes:

* the target ``.vmx`` (while the VM is powered off and the GUI is closed),
* the global user preference file ``~/.vmware/preferences`` (explicit opt-in),
* its own state directory under ``$XDG_STATE_HOME/macopt``.

It never modifies VMware binaries — that stays the Unlocker's job — and it
refuses to guess: unknown state is reported as ``UNKNOWN``, never invented.
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
