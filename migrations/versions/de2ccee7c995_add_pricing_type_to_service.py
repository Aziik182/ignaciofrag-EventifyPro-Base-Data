"""add pricing_type to service

Revision ID: de2ccee7c995
Revises: 0d45b4805414
Create Date: 2026-06-15 16:37:23.161354

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'de2ccee7c995'
down_revision = '0d45b4805414'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('service', schema=None) as batch_op:
        batch_op.add_column(sa.Column('pricing_type', sa.String(length=50), nullable=True))


def downgrade():
    with op.batch_alter_table('service', schema=None) as batch_op:
        batch_op.drop_column('pricing_type')
