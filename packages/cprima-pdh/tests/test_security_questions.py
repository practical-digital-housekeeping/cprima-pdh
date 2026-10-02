"""Security questions: `security_question_N` (visible) and `security_answer_N` (a secret), for any number of pairs."""
import pytest
from pdh_testkit.stubs import E, StubKP

from cprima_pdh import profiles
from cprima_pdh.schema import lookup_term, validate, vocabulary_index

SSET = profiles.load(profiles.DEFAULT)
EXACT, MATCHERS = vocabulary_index(SSET.fields)


def term_of(key):
    hit = lookup_term(key, EXACT, MATCHERS)
    return hit[0] if hit else None


@pytest.mark.parametrize("key", ["security_question", "security_question_1", "security_question_2", "security_question_12"])
def test_questions_are_one_term_for_any_number(key):
    assert term_of(key) == "security_question"


@pytest.mark.parametrize("key", ["security_answer", "security_answer_1", "security_answer_3", "security_answer_12"])
def test_answers_are_one_term_for_any_number(key):
    assert term_of(key) == "security_answer"


@pytest.mark.parametrize("key", ["security_questions", "security_answer_x", "my_security_answer_1", "security_question_"])
def test_other_spellings_are_not_these_terms(key):
    assert term_of(key) not in ("security_question", "security_answer")


def test_the_answer_is_a_protected_secret_and_the_question_is_not():
    answer, question = SSET.fields["security_answer"], SSET.fields["security_question"]
    assert (answer.kind, answer.protected) == ("secret", True)
    assert (question.kind, question.protected) == ("text", False)


def test_each_term_has_an_example():
    assert SSET.example_of("security_question") and SSET.example_of("security_answer")


def rules(entry):
    return {(f.rule, tuple(f.fields)) for f in validate(StubKP([entry]), SSET).findings}


def test_three_pairs_are_known_fields_and_need_nothing_else():
    custom = {f"security_{kind}_{n}": "x" for n in (1, 2, 3) for kind in ("question", "answer")}
    found = rules(E(schema="website", custom=custom, protected=tuple(k for k in custom if "answer" in k)))
    assert not {r for r, _ in found if r.startswith(("unknown-field", "unprotected", "protected"))}


def test_an_unprotected_answer_and_a_protected_question_are_reported():
    entry = E(schema="website", custom={"security_answer_1": "x", "security_question_1": "y"},
              protected=("security_question_1",))
    found = rules(entry)
    assert ("protected:security_answer", ("security_answer_1",)) in found
    assert ("unprotected:security_question", ("security_question_1",)) in found
