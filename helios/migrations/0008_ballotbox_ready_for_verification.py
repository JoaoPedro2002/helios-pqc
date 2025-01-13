from django.db import migrations, models
class Migration(migrations.Migration):

    dependencies = [
        ('helios', '0007_castvote_generic_vote_voter_generic_vote_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='ballotbox',
            name='ready_for_verification',
            field=models.BooleanField(default=False),
        ),
    ]