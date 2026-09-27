import dataclasses

import pytest

from observable.guard.audit import AuditChain, AuditIntegrityError


def test_chain_of_entries_links_and_verifies():
    chain = AuditChain()
    chain.append(agent_id="a1", role="reader", action="tool:crm.read", decision="allow", reason="ok")
    chain.append(agent_id="a1", role="reader", action="tool:crm.read", decision="allow", reason="ok")
    chain.append(agent_id="a2", role="writer", action="tool:crm.write", decision="deny", reason="no grant")

    entries = chain.entries()
    assert len(entries) == 3
    assert entries[0].prev_hash == "0" * 64
    assert entries[1].prev_hash == entries[0].entry_hash
    assert entries[2].prev_hash == entries[1].entry_hash

    chain.verify_chain()  # should not raise


def test_tampering_with_a_field_breaks_verification():
    chain = AuditChain()
    chain.append(agent_id="a1", role="reader", action="tool:crm.read", decision="allow", reason="ok")
    chain.append(agent_id="a1", role="reader", action="tool:crm.delete", decision="deny", reason="no grant")

    # Simulate an attacker editing entry 1's reason directly in the
    # backing store (bypassing append()).
    tampered = dataclasses.replace(chain._entries[1], reason="actually it was allowed")
    chain._entries[1] = tampered

    with pytest.raises(AuditIntegrityError) as exc_info:
        chain.verify_chain()
    assert exc_info.value.broken_at_seq == 1


def test_reordering_entries_breaks_the_chain():
    chain = AuditChain()
    chain.append(agent_id="a1", role="reader", action="tool:crm.read", decision="allow", reason="ok")
    chain.append(agent_id="a1", role="reader", action="tool:crm.write", decision="deny", reason="no grant")

    chain._entries[0], chain._entries[1] = chain._entries[1], chain._entries[0]

    with pytest.raises(AuditIntegrityError):
        chain.verify_chain()


def test_forged_entry_with_correct_hash_but_bad_signature_detected():
    chain = AuditChain()
    chain.append(agent_id="a1", role="reader", action="tool:crm.read", decision="allow", reason="ok")

    import hashlib

    from observable.guard.audit import AuditEntry

    forged_body_entry = dataclasses.replace(chain._entries[0], reason="forged, no real signature")
    forged_hash = hashlib.sha256(forged_body_entry.canonical_body()).hexdigest()
    forged = dataclasses.replace(
        forged_body_entry, entry_hash=forged_hash, signature=b"not-a-real-signature"
    )
    chain._entries[0] = forged

    with pytest.raises(AuditIntegrityError, match="signature"):
        chain.verify_chain()


def test_entries_for_agent_filters():
    chain = AuditChain()
    chain.append(agent_id="a1", role="reader", action="tool:crm.read", decision="allow", reason="ok")
    chain.append(agent_id="a2", role="reader", action="tool:crm.read", decision="allow", reason="ok")
    chain.append(agent_id="a1", role="reader", action="tool:crm.write", decision="deny", reason="no grant")

    a1_entries = chain.entries_for_agent("a1")
    assert len(a1_entries) == 2
    assert all(e.agent_id == "a1" for e in a1_entries)
