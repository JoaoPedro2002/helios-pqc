from helios.views import ELGAMAL_PARAMS
from plainscript.models import LibElection, LibVoter


def helios_benchmark(n_voters, questions, votes):
    import timeit

    setup_t_1 = timeit.default_timer()
    election = LibElection()
    for i in range(1):
        trustee = election.generate_trustee(ELGAMAL_PARAMS)
        election.trustees.append(trustee)
    election.questions = questions
    setup_t_2 = timeit.default_timer()

    register_t_1 = timeit.default_timer()
    election.voters = [LibVoter() for _ in range(n_voters)]
    election.freeze()
    register_t_2 = timeit.default_timer()

    voting_t_1 = timeit.default_timer()

    for i in range(n_voters):
        voter = election.voters[i]
        vote = votes[i]
        voter.vote = election.encrypt_ballot(str(vote))
        voter.vote.verify(election)

    voting_t_2 = timeit.default_timer()

    counting_t_1 = timeit.default_timer()
    election.compute_tally()

    for trustee in election.trustees:
        election.lib_trustee_decrypt(trustee)
    election.combine_decryptions()
    counting_t_2 = timeit.default_timer()
    for trustee in election.trustees:
        trustee.verify_decryption_proofs()
    counting_t_3 = timeit.default_timer()

    dec_t = counting_t_2 - counting_t_1
    ver_t = counting_t_3 - counting_t_2

    setup_t = setup_t_2 - setup_t_1
    register_t = register_t_2 - register_t_1
    voting_t = voting_t_2 - voting_t_1
    counting_t = counting_t_3 - counting_t_1

    return (setup_t, register_t, voting_t, counting_t), (setup_t, register_t, voting_t, 0, dec_t, ver_t)