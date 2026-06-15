"""fix reservation swapped fk constraints

The original migration (986b4bdee3b5) created the reservation table with
proveedor_id and paquete_evento_id pointing at the wrong tables (swapped).
Later migrations added correctly-named FK constraints on top, but never
dropped the original unnamed ones, so a fresh database ends up with two
conflicting FK constraints per column. This only went unnoticed locally
because SQLite does not enforce foreign keys unless PRAGMA foreign_keys=ON
is set. Postgres enforces them unconditionally, so this would break
inserts/updates on a freshly migrated production database.

This rebuilds the table from a clean definition instead of patching
constraints by name, since the original (wrong) constraints were created
unnamed and can't be targeted directly outside of an autogenerate session.

Revision ID: 18458733b237
Revises: a1b2c3d4e5f6
Create Date: 2026-06-15 19:26:05.147042

"""
import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision = '18458733b237'
down_revision = 'a1b2c3d4e5f6'
branch_labels = None
depends_on = None


def upgrade():
    correct = sa.Table(
        'reservation', sa.MetaData(),
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('status', sa.String(length=50), nullable=False),
        sa.Column('date_time_reservation', sa.DateTime(), nullable=False),
        sa.Column('precio', sa.Float(), nullable=False),
        sa.Column('proveedor_id', sa.Integer(), nullable=False),
        sa.Column('paquete_evento_id', sa.Integer(), nullable=True),
        sa.Column('usuario_id', sa.Integer(), nullable=False),
        sa.Column('service_id', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['proveedor_id'], ['profile.id'], name='reservation_proveedor_id_fkey'),
        sa.ForeignKeyConstraint(['paquete_evento_id'], ['event_pack.id'], name='reservation_paquete_evento_id_fkey'),
        sa.ForeignKeyConstraint(['usuario_id'], ['user.id']),
        sa.ForeignKeyConstraint(['service_id'], ['service.id']),
    )
    with op.batch_alter_table('reservation', copy_from=correct, recreate='always'):
        pass


def downgrade():
    swapped = sa.Table(
        'reservation', sa.MetaData(),
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('status', sa.String(length=50), nullable=False),
        sa.Column('date_time_reservation', sa.DateTime(), nullable=False),
        sa.Column('precio', sa.Float(), nullable=False),
        sa.Column('proveedor_id', sa.Integer(), nullable=False),
        sa.Column('paquete_evento_id', sa.Integer(), nullable=True),
        sa.Column('usuario_id', sa.Integer(), nullable=False),
        sa.Column('service_id', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['proveedor_id'], ['profile.id'], name='reservation_proveedor_id_fkey'),
        sa.ForeignKeyConstraint(['paquete_evento_id'], ['event_pack.id'], name='reservation_paquete_evento_id_fkey'),
        sa.ForeignKeyConstraint(['proveedor_id'], ['event_pack.id']),
        sa.ForeignKeyConstraint(['paquete_evento_id'], ['profile.id']),
        sa.ForeignKeyConstraint(['usuario_id'], ['user.id']),
        sa.ForeignKeyConstraint(['service_id'], ['service.id']),
    )
    with op.batch_alter_table('reservation', copy_from=swapped, recreate='always'):
        pass
