"""Add for client flag to playlist

Revision ID: 98c90621cf58
Revises: 5b7fa3e51701
Create Date: 2019-11-04 20:10:43.256743

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "98c90621cf58"
down_revision = "5b7fa3e51701"
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column(
        "playlist",
        sa.Column("for_client", sa.Boolean(), nullable=True, default=False),
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column("playlist", "for_client")
    # ### end Alembic commands ###
