from helios.models import *
from helios.workflows import homomorphic


class LibElection(Election):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.uid = None
        self.admin = None
        self.voters = list()
        self.frozen_at = None
        self.trustees = list()
        self.voting_starts_at = None
        self.voting_ends_at = None
        self.voters_hash = None

    @property
    def num_cast_votes(self):
        return len(list(filter(lambda v: v.vote is not None, self.voters)))

    @property
    def num_voters(self):
        return len(self.voters)

    @property
    def num_trustees(self):
        return len(self.trustees)

    def compute_tally(self, verify_p=False):
        tally = self.init_tally()
        for voter in filter(lambda v: v.vote is not None, self.voters):
            tally.add_vote(voter.vote, verify_p)
        self.encrypted_tally = tally

    def generate_trustee(self, params):
        keypair = params.generate_keypair()

        trustee = LibTrustee()
        trustee.uuid = uuid.uuid4().hex
        trustee.election = self
        trustee.public_key = keypair.pk
        trustee.secret_key = keypair.sk
        trustee.secret = utils.random_string(12)
        trustee.public_key_hash = datatypes.LDObject.instantiate(trustee.public_key, datatype='legacy/EGPublicKey').hash

        trustee.pok = trustee.secret_key.prove_sk(algs.DLog_challenge_generator)

        return trustee
    @staticmethod
    def create_question(answers: list, minimum, maximum, result_type='relative'):
        return {
            'answers': answers,
            'min': minimum,
            'max': maximum,
            'result_type': result_type,  # absolute
            'tally_type': 'homomorphic',
            'choice_type': 'approval',
        }

    def freeze(self):
        trustees = self.trustees
        combined_pk = trustees[0].public_key
        for trustee in trustees[1:]:
            combined_pk = combined_pk * trustee.public_key

        self.public_key = combined_pk

    def encrypt_ballot(self, answers) -> homomorphic.EncryptedVote:
        answers_list = utils.from_json(answers)
        from helios.workflows import homomorphic

        ev = homomorphic.EncryptedVote.fromElectionAndAnswers(self, answers_list)
        return ev

    @property
    def get_helios_trustee(self):
        trustee = list(filter(lambda t: t.secret_key is not None, self.trustees))
        return trustee[0] if len(trustee) else None

    @property
    def has_helios_trustee(self):
        return self.get_helios_trustee is not None

    def helios_trustee_decrypt(self):
        trustee = self.get_helios_trustee
        tally = self.encrypted_tally
        tally.init_election(self)

        factors, proof = tally.decryption_factors_and_proofs(trustee.secret_key)

        trustee.decryption_factors = factors
        trustee.decryption_proofs = proof
        return trustee

    def lib_trustee_decrypt(self, trustee):
        tally = self.encrypted_tally
        tally.init_election(self)

        factors, proof = tally.decryption_factors_and_proofs(trustee.secret_key)

        trustee.decryption_factors = factors
        trustee.decryption_proofs = proof
        return trustee

    def combine_decryptions(self):
        trustees = self.trustees
        decryption_factors = [trustee.decryption_factors for trustee in trustees]
        self.result = self.encrypted_tally.decrypt_from_factors(decryption_factors, self.public_key)

    def __hash__(self):
        return hash(self.uuid)


class LibTrustee(Trustee):
    election = None
    secret = None
    # public key
    public_key = None
    public_key_hash = None
    # secret key
    # if the secret key is present, this means
    # Helios is playing the role of the trustee.
    secret_key = None
    # proof of knowledge of secret key
    pok = None
    # decryption factors and proofs
    decryption_factors = None
    decryption_proofs = None

    def __hash__(self):
        return hash(self.uuid)


class LibVoter(Voter):
    uid = None
    vote = None
    weight = int(1)
    cumulative_weight = list()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.vote_hash = None

    @property
    def voter_type(self):
        return "password"

    def store_vote(self, cast_vote):
        if self.cast_at and self.cast_at > cast_vote.cast_at:
            return

        self.vote = cast_vote.vote
        self.vote_hash = cast_vote.vote_hash
        self.cast_at = cast_vote.cast_at
        self.cumulative_weight = cast_vote.cumulative_weight
    def __hash__(self):
        return hash(self.uuid)