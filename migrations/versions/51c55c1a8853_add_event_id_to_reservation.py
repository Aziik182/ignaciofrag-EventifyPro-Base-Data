"""add event_id to reservation

Revision ID: 51c55c1a8853
Revises: a67e202b6390
Create Date: 2026-06-15 21:39:16.251366

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '51c55c1a8853'
down_revision = 'a67e202b6390'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('reservation', schema=None) as batch_op:
        batch_op.add_column(sa.Column('event_id', sa.Integer(), nullable=True))
        batch_op.create_foreign_key('fk_reservation_event_id', 'events', ['event_id'], ['id'])


def downgrade():
    with op.batch_alter_table('reservation', schema=None) as batch_op:
        batch_op.drop_constraint('fk_reservation_event_id', type_='foreignkey')
        batch_op.drop_column('event_id')
