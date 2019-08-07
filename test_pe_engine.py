import pytest

FILE_PATH = r"E:\Se-Ok_Jeon\OneDrive - Chonnam National University" \
            r"\installer\Windows\Xshell-6.0.0118p.exe"


@pytest.fixture
def pechecksec():
    import pe_engine
    return pe_engine.PeCheckSec(FILE_PATH)


def test_pechecksec_init_(pechecksec):


