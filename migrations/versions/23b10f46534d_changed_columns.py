"""Changed Columns

Revision ID: 23b10f46534d
Revises: e3f7585367c3
Create Date: 2024-06-17 14:57:35.936142

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = '23b10f46534d'
down_revision = 'e3f7585367c3'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('iptable5')
    with op.batch_alter_table('iptable', schema=None) as batch_op:
        batch_op.add_column(sa.Column('class', sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column('gateway', sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column('ip_address', sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column('host', sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column('part', sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column('name', sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column('place', sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column('phone', sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column('etcs', sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column('date', sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column('num', sa.String(length=255), nullable=True))
        batch_op.drop_column('Num')
        batch_op.drop_column('Phone')
        batch_op.drop_column('Gateway')
        batch_op.drop_column('Class')
        batch_op.drop_column('Place')
        batch_op.drop_column('IP Address')
        batch_op.drop_column('Part')
        batch_op.drop_column('Host')
        batch_op.drop_column('Etcs')
        batch_op.drop_column('Date')
        batch_op.drop_column('Name')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('iptable', schema=None) as batch_op:
        batch_op.add_column(sa.Column('Name', mysql.VARCHAR(length=255), nullable=True))
        batch_op.add_column(sa.Column('Date', mysql.VARCHAR(length=255), nullable=True))
        batch_op.add_column(sa.Column('Etcs', mysql.VARCHAR(length=255), nullable=True))
        batch_op.add_column(sa.Column('Host', mysql.VARCHAR(length=255), nullable=True))
        batch_op.add_column(sa.Column('Part', mysql.VARCHAR(length=255), nullable=True))
        batch_op.add_column(sa.Column('IP Address', mysql.VARCHAR(length=255), nullable=True))
        batch_op.add_column(sa.Column('Place', mysql.VARCHAR(length=255), nullable=True))
        batch_op.add_column(sa.Column('Class', mysql.VARCHAR(length=255), nullable=True))
        batch_op.add_column(sa.Column('Gateway', mysql.VARCHAR(length=255), nullable=True))
        batch_op.add_column(sa.Column('Phone', mysql.VARCHAR(length=255), nullable=True))
        batch_op.add_column(sa.Column('Num', mysql.VARCHAR(length=255), nullable=True))
        batch_op.drop_column('num')
        batch_op.drop_column('date')
        batch_op.drop_column('etcs')
        batch_op.drop_column('phone')
        batch_op.drop_column('place')
        batch_op.drop_column('name')
        batch_op.drop_column('part')
        batch_op.drop_column('host')
        batch_op.drop_column('ip_address')
        batch_op.drop_column('gateway')
        batch_op.drop_column('class')

    op.create_table('iptable5',
    sa.Column('id', mysql.INTEGER(display_width=11), autoincrement=True, nullable=False),
    sa.Column('gateway', mysql.VARCHAR(length=255), nullable=True),
    sa.Column('ip', mysql.VARCHAR(length=255), nullable=True),
    sa.Column('host', mysql.VARCHAR(length=255), nullable=True),
    sa.Column('part', mysql.VARCHAR(length=255), nullable=True),
    sa.Column('name', mysql.VARCHAR(length=255), nullable=True),
    sa.Column('place', mysql.VARCHAR(length=255), nullable=True),
    sa.Column('phone', mysql.VARCHAR(length=255), nullable=True),
    sa.Column('etcs', mysql.VARCHAR(length=255), nullable=True),
    sa.Column('date', mysql.VARCHAR(length=255), nullable=True),
    sa.Column('class', mysql.VARCHAR(length=255), nullable=True),
    sa.Column('num', mysql.VARCHAR(length=255), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    mysql_collate='utf8mb4_general_ci',
    mysql_default_charset='utf8mb4',
    mysql_engine='InnoDB'
    )
    # ### end Alembic commands ###
