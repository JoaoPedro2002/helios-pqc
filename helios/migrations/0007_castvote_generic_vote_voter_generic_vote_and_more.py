# Generated by Django 5.0 on 2025-01-10 07:54

import django.db.models.deletion
import helios.datatypes
import helios.datatypes.djangofield
import helios_auth.jsonfield
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('helios', '0006_election_election_method_ballotbox'),
    ]

    operations = [
        migrations.AddField(
            model_name='castvote',
            name='generic_vote',
            field=models.JSONField(null=True),
        ),
        migrations.AddField(
            model_name='voter',
            name='generic_vote',
            field=models.JSONField(null=True),
        ),
        migrations.AlterField(
            model_name='castvote',
            name='vote',
            field=helios.datatypes.djangofield.LDObjectField(null=True),
        ),
        migrations.CreateModel(
            name='LbvsVoter',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('uuid', models.CharField(max_length=50)),
                ('voter_phone', models.CharField(max_length=250, null=True)),
                ('vvk', helios_auth.jsonfield.JSONField(null=True)),
                ('voter', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='helios.voter')),
            ],
            options={
                'abstract': False,
            },
            bases=(models.Model, helios.datatypes.LDObjectContainer),
        ),
    ]
