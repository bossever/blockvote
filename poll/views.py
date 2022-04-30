from django.shortcuts import render, redirect
from . import models
import math
import datetime
from django.contrib.admin.forms import AuthenticationForm
from hashlib import sha512, sha256
from .merkleTree import merkleTree

result_calculated = False


def home(request):
    return render(request, "poll/home.html")


def vote(request):
    candidates = models.Candidate.objects.all()
    context = {"candidates": candidates}
    return render(request, "poll/vote.html", context)


def login(request):

    if request.method == "POST":
        form = AuthenticationForm(data=request.POST)

        if form.is_valid():
            return redirect("vote")
        else:
            form = AuthenticationForm()
    return render(request, "poll/login.html/")


def create(request, pk):
    print(request.user)
    voter = models.Voter.objects.filter(username=request.user.username)[0]

    if request.method == "POST" and request.user.is_authenticated \
            and not voter.has_voted:
        vote = pk
        lenVoteList = len(models.Vote.objects.all())

        if (lenVoteList > 0):
            block_id = math.floor(lenVoteList / 5) + 1
        else:
            block_id = 1
        private_key = {
            "n": int(request.POST.get("privateKey_n")),
            "d": int(request.POST.get("privateKey_d"))
        }
        public_key = {
            "n": int(voter.public_key_n),
            "e": int(voter.public_key_e)
        }

        # Create ballot as string vector
        timestamp = datetime.datetime.now().timestamp()
        ballot = f"{vote}|{timestamp}"
        print(f"-> Casted ballot: {ballot}")

        hash_ballot = int.from_bytes(sha512(ballot.encode()).digest(), byteorder="big")
        print(f"-> Hash of ballot: {hash_ballot}")

        signature = pow(hash_ballot, private_key["d"], private_key["n"])
        print(f"-> Signature: {signature}")

        hash_signature = pow(signature, public_key["e"], public_key["n"])
        print(f"-> Hash of signature: {hash_signature}")

        if(hash_signature == hash_ballot):
            new_vote = models.Vote(vote=pk)
            new_vote.block_id = block_id
            new_vote.save()
            status = "Ballot signed successfully."
            error = False
        else:
            status = "Authentication Error! Ballot not signed."
            error = True
        context = {
            "ballot": ballot,
            "signature": signature,
            "status": status,
            "error": error,
        }
        print("-> Error: " + str(error))

        if not error:
            return render(request, "poll/status.html", context)

    return render(request, "poll/failure.html", context)


prev_hash = "0" * 64


def seal(request):

    if request.method == "POST":

        if (len(models.Vote.objects.all()) % 5 != 0):
            redirect("login")
        else:
            global prev_hash
            transactions = models.Vote.objects.order_by("block_id").reverse()
            transactions = list(transactions)[:5]
            block_id = transactions[0].block_id

            str_transactions = [str(x) for x in transactions]

            merkle_tree = merkleTree.merkleTree()
            merkle_tree.makeTreeFromArray(str_transactions)
            merkle_hash = merkle_tree.calculateMerkleRoot()

            nonce = 0
            timestamp = datetime.datetime.now().timestamp()

            while True:
                self_hash = sha256(f"{prev_hash}{merkle_hash}{nonce}\
                                    {timestamp}".encode()).hexdigest()

                if self_hash[0] == "0":
                    break
                nonce += 1

            block = models.Block(id=block_id,
                                 prev_hash=prev_hash,
                                 self_hash=self_hash,
                                 merkle_hash=merkle_hash,
                                 nonce=nonce,
                                 timestamp=timestamp)
            prev_hash = self_hash
            block.save()
            print("Block {} has been mined".format(block_id))

    return redirect("home")


def retDate(vote):
    vote.timestamp = datetime.datetime.fromtimestamp(vote.timestamp)
    return vote


def verify(request):

    if request.method == "GET":
        message = ""
        tampered_block_list = verifyVotes()
        votes = []

        if tampered_block_list:
            message = f"Verification Failed. Following blocks have been\
                        tampered --> {tampered_block_list}. The authority will\
                        resolve the issue"
            error = True
        else:
            message = "Verification successful. All votes are intact!"
            error = False
            vote_set = models.Vote.objects.order_by("timestamp")
            votes = [retDate(vote) for vote in vote_set]

        context = {"verification": message, "error": error, "votes": votes}
        return render(request, "poll/verification.html", context)


def result(request):

    if request.method == "GET":
        global result_calculated
        vote_verification = verifyVotes()

        if len(vote_verification):
            return render(
                request,
                "poll/verification.html",
                {
                    "verification": f"Verification failed. Votes have been\
                    tampered in following blocks --> {vote_verification}.",
                    "error": True
                }
            )

        if not result_calculated:
            list_of_votes = models.Vote.objects.all()

            for vote in list_of_votes:
                print("Before counting -> " + str(vote.counted))
                if vote.counted is False:
                    candidate = models.Candidate.objects. \
                        filter(candidateID=vote.vote)[0]
                    candidate.count += 1
                    candidate.save()
                    vote.counted = True
                    vote.save()
                    print("After counting -> " + str(vote.counted))

            result_calculated = True

        context = {
            "candidates": models.Candidate.objects.order_by("count").reverse(),
            "winner": models.Candidate.objects.order_by("count").reverse()[0]
        }
        return render(request, "poll/results.html", context)


def verifyVotes():
    block_count = models.Block.objects.count()
    tampered_block_list = []

    for i in range(1, block_count+1):
        block = models.Block.objects.get(id=i)
        transactions = models.Vote.objects.filter(block_id=i)
        str_transactions = [str(x) for x in transactions]
        merkle_tree = merkleTree.merkleTree()
        merkle_tree.makeTreeFromArray(str_transactions)
        merkle_tree.calculateMerkleRoot()

        if (block.merkle_hash == merkle_tree.getMerkleRoot()):
            continue
        else:
            tampered_block_list.append(i)

    return tampered_block_list
