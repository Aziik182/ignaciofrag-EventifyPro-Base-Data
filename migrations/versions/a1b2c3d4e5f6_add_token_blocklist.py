"""add token blocklist

Revision ID: a1b2c3d4e5f6
Revises: de2ccee7c995
Create Date: 2026-06-15 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = 'a1b2c3d4e5f6'
down_revision = 'de2ccee7c995'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'token_blocklist',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('jti', sa.String(length=36), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )
    with op.batch_alter_table('token_blocklist', schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f('ix_token_blocklist_jti'), ['jti'], unique=True
        )


def downgrade():
    with op.batch_alter_table('token_blocklist', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_token_blocklist_jti'))
    op.drop_table('token_blocklist')
