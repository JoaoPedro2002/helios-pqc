"""
Forms for Helios
"""
from django import forms
from django.conf import settings

from .fields import SplitDateTimeField
from .models import Election
from .widgets import SplitSelectDateTimeWidget


class ElectionForm(forms.Form):
  short_name = forms.SlugField(max_length=40, help_text='no spaces, will be part of the URL for your election, e.g. my-club-2010')
  name = forms.CharField(max_length=100, widget=forms.TextInput(attrs={'size':60}), help_text='the pretty name for your election, e.g. My Club 2010 Election')
  description = forms.CharField(max_length=4000, widget=forms.Textarea(attrs={'cols': 70, 'wrap': 'soft'}), required=False)
  election_type = forms.ChoiceField(label="type", choices = Election.ELECTION_TYPES)
  use_voter_aliases = forms.BooleanField(required=False, initial=False, help_text='If selected, voter identities will be replaced with aliases, e.g. "V12", in the ballot tracking center')
  #use_advanced_audit_features = forms.BooleanField(required=False, initial=True, help_text='disable this only if you want a simple election with reduced security but a simpler user interface')
  randomize_answer_order = forms.BooleanField(required=False, initial=False, help_text='enable this if you want the answers to questions to appear in random order for each voter')
  private_p = forms.BooleanField(required=False, initial=False, label="Private?", help_text='A private election is only visible to registered voters.')

  ###### Params for the PQC scheme ######
  election_method = forms.ChoiceField(label="Protocol", choices=Election.ELECTION_METHODS,
                                      initial=Election.ELECTION_METHODS[0][0], required=False)
  shuffle_server_url = forms.CharField(required=False, initial="", label="Shuffle Server URL", help_text='URL of a server that will shuffle the ballots')
  return_code_server_url = forms.CharField(required=False, initial="", label="Return Code Server URL", help_text='URL of a server that will receive cast vote records and return codes')
  auditors_urls = forms.CharField(required=False, initial="", label="Auditors URLs", help_text='Comma-separated list of URLs of auditors that will receive cast vote records and return codes')
  ########################################
  help_email = forms.CharField(required=False, initial="", label="Help Email Address", help_text='An email address voters should contact if they need help.')
  
  if settings.ALLOW_ELECTION_INFO_URL:
    election_info_url = forms.CharField(required=False, initial="", label="Election Info Download URL", help_text="the URL of a PDF document that contains extra election information, e.g. candidate bios and statements")
  
  # times
  voting_starts_at = SplitDateTimeField(help_text = 'UTC date and time when voting begins',
                                   widget=SplitSelectDateTimeWidget, required=False)
  voting_ends_at = SplitDateTimeField(help_text = 'UTC date and time when voting ends',
                                   widget=SplitSelectDateTimeWidget, required=False)

  def clean(self):
    election_method = self.cleaned_data.get("election_method")
    if election_method == Election.ELECTION_METHODS[0][0]:
        self.cleaned_data['shuffle_server_url'] = ''
        self.cleaned_data['return_code_server_url'] = ''
        self.cleaned_data['auditors_urls'] = ''
    else:
        if not self.cleaned_data.get("shuffle_server_url"):
            self.add_error('shuffle_server_url', "Shuffle Server URL is required")
        if not self.cleaned_data.get("return_code_server_url"):
            self.add_error('return_code_server_url', "Return Code Server URL is required")
        if not self.cleaned_data.get("auditors_urls"):
            self.add_error('auditors_urls', "Auditors URLs are required")

    return self.cleaned_data

class ElectionTimeExtensionForm(forms.Form):
  voting_extended_until = SplitDateTimeField(help_text = 'UTC date and time voting extended to',
                                   widget=SplitSelectDateTimeWidget, required=False)
  
class EmailVotersForm(forms.Form):
  subject = forms.CharField(max_length=80)
  body = forms.CharField(max_length=4000, widget=forms.Textarea)
  send_to = forms.ChoiceField(label="Send To", initial="all", choices= [('all', 'all voters'), ('voted', 'voters who have cast a ballot'), ('not-voted', 'voters who have not yet cast a ballot')])

class TallyNotificationEmailForm(forms.Form):
  subject = forms.CharField(max_length=80)
  body = forms.CharField(max_length=2000, widget=forms.Textarea, required=False)
  send_to = forms.ChoiceField(label="Send To", choices= [('all', 'all voters'), ('voted', 'only voters who cast a ballot'), ('none', 'no one -- are you sure about this?')])

class VoterPasswordForm(forms.Form):
  voter_id = forms.CharField(max_length=50, label="Voter ID")
  password = forms.CharField(widget=forms.PasswordInput(), max_length=100)

